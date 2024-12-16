-module(node_manager).
-export([init/0, start_node/1, stop_node/0, register_node/1, unregister_node/1,
         broadcast_message/2, propagate_registration/1, handle_incoming_message/2,
         extract_nodes/1, get_active_nodes/0, synchronize_active_nodes/0,
         register_user/2, login_user/2, send_message/2, get_messages/0, create_group/2,
         add_user_to_group/2, send_group_message/2, get_group_messages/1, http_request/4,
         logout_user/0]).

-define(ACTIVE_NODES, active_nodes).
-define(ACTIVE_USERS, active_users).
-define(ACTIVE_SESSIONS, active_sessions).
-define(CURRENT_SESSION, current_session).

init() ->
    ensure_inets_started(),
    case ets:info(?ACTIVE_NODES) of
        undefined ->
            ets:new(?ACTIVE_NODES, [named_table, set, public]),
            io:format("Node manager initialized.~n");
        _ ->
            io:format("Node manager already initialized.~n")
    end,

    case ets:info(?ACTIVE_USERS) of
        undefined ->
            ets:new(?ACTIVE_USERS, [named_table, set, public]),
            ok;
        _ ->
            ok
    end,

    case ets:info(?ACTIVE_SESSIONS) of
        undefined ->
            ets:new(?ACTIVE_SESSIONS, [named_table, set, public]),
            ok;
        _ ->
            ok
    end,

    % Create or reset the current_session table
    case ets:info(?CURRENT_SESSION) of
        undefined ->
            ets:new(?CURRENT_SESSION, [named_table, set, public]),
            ok;
        _ ->
            ets:delete_all_objects(?CURRENT_SESSION),
            ok
    end,

    KnownNodes = fetch_nodes_from_database(),
    lists:foreach(fun(NodeName) -> ensure_node_connection(NodeName) end, KnownNodes),
    start_node(node()),
    synchronize_active_nodes().

register_user(Username, Password) ->
    ensure_inets_started(),
    URL = "http://localhost:5000/register",
    Data = io_lib:format("{\"username\": \"~s\", \"password\": \"~s\"}", [Username, Password]),
    Headers = [{"Content-Type", "application/json"}],
    case httpc:request(post, {URL, Headers, "application/json", Data}, [], []) of
        {ok, {{_, 201, _}, _, _}} ->
            io:format("User ~p registered successfully.~n", [Username]),
            {ok, "User registered successfully."};
        {ok, {{_, 400, _}, _, Body}} ->
            io:format("Failed to register user ~p: ~s~n", [Username, Body]),
            {error, Body};
        {ok, {{_, 500, _}, _, Body}} ->
            io:format("Server error while registering user ~p: ~s~n", [Username, Body]),
            {error, Body};
        {error, Reason} ->
            io:format("HTTP request failed while registering user ~p: ~p~n", [Username, Reason]),
            {error, Reason}
    end.


% Store {Username, Token} after login
login_user(Username, Password) ->
    case get_current_user() of
        {ok, ExistingUsername} ->
            io:format("Cannot login as ~p. User ~p is already logged in. Please logout first.~n", [Username, ExistingUsername]),
            {error, "A user is already logged in. Please logout first."};
        {error, _Reason} ->
            proceed_login(Username, Password)
    end.

proceed_login(Username, Password) ->
    ensure_inets_started(),
    URL = "http://localhost:5000/login",
    Data = io_lib:format("{\"username\": \"~s\", \"password\": \"~s\"}", [Username, Password]),
    Headers = [{"Content-Type", "application/json"}],
    case httpc:request(post, {URL, Headers, "application/json", Data}, [], []) of
        {ok, {{_, 200, _}, _, Body}} ->
            io:format("Login successful for user ~p.~n", [Username]),
            Token = extract_json_value(Body, "token"),
            ets:insert(?ACTIVE_SESSIONS, {Username, Token}),
            ets:delete_all_objects(?CURRENT_SESSION),
            ets:insert(?CURRENT_SESSION, {current_user, Username}),
            io:format("Current user set to ~p after login.~n", [Username]),
            {ok, Token};
        {ok, {{_, 401, _}, _, Body}} ->
            io:format("Invalid credentials for user ~p: ~s~n", [Username, Body]),
            {error, "Invalid credentials"};
        {ok, {{_, 400, _}, _, Body}} ->
            io:format("Bad request login user ~p: ~s~n", [Username, Body]),
            {error, Body};
        {ok, {{_, 500, _}, _, Body}} ->
            io:format("Server error login user ~p: ~s~n", [Username, Body]),
            {error, Body};
        {error, Reason} ->
            io:format("HTTP request failed while logging in user ~p: ~p~n", [Username, Reason]),
            {error, Reason}
    end.


logout_user() ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    URL = "http://localhost:5000/logout",
                    Data = io_lib:format("{\"token\": \"~s\"}", [Token]),
                    Headers = [{"Content-Type", "application/json"}],
                    case http_request(post, URL, Headers, Data) of
                        {ok, _Body} ->
                            % Remove user token and current_user from ETS
                            ets:delete_all_objects(?CURRENT_SESSION),
                            ets:delete(?ACTIVE_SESSIONS, Username),
                            io:format("User ~p logged out successfully.~n", [Username]),
                            ok;
                        {error, Reason} ->
                            io:format("Failed to logout: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("No user token found: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot logout: ~s~n", [Reason]),
            {error, Reason}
    end.

% Retrieve the currently set user's username
get_current_user() ->
    case ets:lookup(?CURRENT_SESSION, current_user) of
        [{current_user, Username}] -> {ok, Username};
        [] -> {error, "Access denied: You need to login first."}
    end.


% Retrieve a token from a username
get_user_token(Username) ->
    case ets:lookup(?ACTIVE_SESSIONS, Username) of
        [{Username, Token}] -> {ok, Token};
        [] -> {error, "User not logged in or token not stored"}
    end.


% Send message using the current user's token
send_message(Receiver, Message) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    send_message_with_token(Token, Receiver, Message);
                {error, Reason} ->
                    io:format("Cannot send message: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot send message: ~s~n", [Reason]),
            {error, Reason}
    end.


send_message_with_token(Token, Receiver, Message) ->
    ensure_inets_started(),
    URL = "http://localhost:5000/send_message",
    Data = io_lib:format("{\"token\": \"~s\", \"receiver\": \"~s\", \"message\": \"~s\"}", [Token, Receiver, Message]),
    Headers = [{"Content-Type", "application/json"}],
    case httpc:request(post, {URL, Headers, "application/json", Data}, [], []) of
        {ok, {{_, 201, _}, _, _}} ->
            io:format("Message sent to ~p successfully.~n", [Receiver]),
            ok;
        {ok, {{_, Code, _}, _, Body}} when Code =:= 401; Code =:= 400 ->
            io:format("Failed to send message: ~s~n", [Body]),
            {error, Body};
        {ok, {{_, 500, _}, _, Body}} ->
            io:format("Server error sending message: ~s~n", [Body]),
            {error, Body};
        {error, Reason} ->
            io:format("HTTP request failed while sending message: ~p~n", [Reason]),
            {error, Reason}
    end.


% Get messages for the current user
get_messages() ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    get_messages_with_token(Token);
                {error, Reason} ->
                    io:format("Cannot get messages: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot get messages: ~s~n", [Reason]),
            {error, Reason}
    end.

get_messages_with_token(Token) ->
    ensure_inets_started(),
    URL = "http://localhost:5000/get_messages?token=" ++ Token,
    Headers = [{"Accept", "application/json"}],
    case httpc:request(get, {URL, Headers}, [], []) of
        {ok, {{_, 200, _}, _, Body}} ->
            io:format("Messages retrieved successfully.~n"),
            io:format("Raw Body: ~s~n", [Body]),
            {ok, Body};
        {ok, {{_, Code, _}, _, Body}} when Code =:= 401; Code =:= 400 ->
            io:format("Failed to retrieve messages: ~s~n", [Body]),
            {error, Body};
        {ok, {{_, 500, _}, _, Body}} ->
            io:format("Server error retrieving messages: ~s~n", [Body]),
            {error, Body};
        {error, Reason} ->
            io:format("HTTP request failed while retrieving messages: ~p~n", [Reason]),
            {error, Reason}
    end.


extract_json_value(Body, Key) ->
    Regex = io_lib:format("\"~s\"\\s*:\\s*\"([^\"]+)\"", [Key]),
    case re:run(Body, list_to_binary(Regex), [global, {capture, all_but_first, list}]) of
        {match, [[Value]]} -> Value;
        _ -> undefined
    end.


fetch_nodes_from_database() ->
    URL = "http://localhost:5000/get_active_nodes",
    Headers = [{"Accept", "application/json"}],
    io:format("DEBUG: Sending GET request to URL: ~p~n", [URL]),
    case httpc:request(get, {URL, Headers}, [], []) of
        {ok, {{_, 200, _}, _, Body}} ->
            Nodes = extract_nodes(Body),
            Nodes;
        {ok, {{_, StatusCode, _}, _, ResponseBody}} ->
            io:format("ERROR: Received status code ~p with body: ~p~n", [StatusCode, ResponseBody]),
            [];
        {error, Reason} ->
            io:format("ERROR: HTTP request failed. Reason: ~p~n", [Reason]),
            []
    end.

extract_nodes(JSON) ->
    {match, Matches} = re:run(
      JSON,
      <<"\"node_name\":\\s*\"([^\"]+)\"">>,
      [global, {capture, all_but_first, list}]
    ),
    Nodes = [Node || [Node] <- Matches],
    io:format("Extracted Nodes: ~p~n", [Nodes]),
    Nodes.

ensure_node_connection(Node) ->
    NodeAtom = list_to_atom(Node),
    case net_adm:ping(NodeAtom) of
        pong -> io:format("Successfully connected to ~p.~n", [NodeAtom]);
        pang -> io:format("Failed to connect to ~p.~n", [NodeAtom])
    end.

start_node(NodeName) ->
    net_kernel:start([NodeName, shortnames]),
    register_node(node()).


stop_node() ->
    unregister_node(node()),
    net_kernel:stop().

register_node(Node) ->
    case ets:lookup(?ACTIVE_NODES, Node) of
        [] ->
            ets:insert(?ACTIVE_NODES, {Node, connected}),
            io:format("Node ~p registered locally.~n", [Node]),
            update_node_in_database(Node, connected);
        _ ->
            io:format("Node ~p is already registered locally.~n", [Node])
    end,
    lists:foreach(
        fun(ConnectedNode) ->
            rpc:call(ConnectedNode, node_manager, propagate_registration, [Node])
        end, nodes()).

update_node_in_database(Node, Status) ->
    ensure_inets_started(),
    URL = "http://localhost:5000/register_node",
    Data = io_lib:format("{\"node_name\": \"~s\", \"status\": \"~s\"}", [atom_to_list(Node), atom_to_list(Status)]),
    case httpc:request(post, {URL, [], "application/json", Data}, [], []) of
        {ok, {{_, 200, _}, _, _}} ->
            io:format("Node ~p updated in the database successfully.~n", [Node]);
        {ok, {{_, StatusCode, _}, _, ResponseBody}} ->
            io:format("Failed to update node ~p. Status: ~p, Response: ~p~n", [Node, StatusCode, ResponseBody]);
        {error, Reason} ->
            io:format("Failed to update node ~p in the database: ~p~n", [Node, Reason])
    end.

propagate_registration(Node) ->
    case ets:lookup(?ACTIVE_NODES, Node) of
        [] ->
            ets:insert(?ACTIVE_NODES, {Node, connected}),
            io:format("Node ~p registered remotely.~n", [Node]);
        _ ->
            io:format("Node ~p is already registered remotely.~n", [Node])
    end.

unregister_node(Node) ->
    case ets:lookup(?ACTIVE_NODES, Node) of
        [{Node, _}] ->
            ets:delete(?ACTIVE_NODES, Node),
            io:format("Node ~p unregistered locally.~n", [Node]);
        [] ->
            io:format("Node ~p not found in active_nodes, skipping local removal.~n", [Node])
    end,

    case remove_node_from_database(Node) of
        ok ->
            io:format("Node ~p removed from the database successfully.~n", [Node]),
            ok;
        {error, {404, _}} ->
            io:format("Node ~p not found in the database, skipping database removal.~n", [Node]),
            ok;
        {error, Reason} ->
            io:format("Failed to remove node ~p from the database: ~p~n", [Node, Reason]),
            {error, Reason}
    end.

remove_node_from_database(Node) ->
    ensure_inets_started(),
    NodeName = atom_to_list(Node),
    EncodedNodeName = uri_string:quote(NodeName),
    URL = "http://localhost:5000/remove_node/" ++ EncodedNodeName,
    Headers = [{"Content-Type", "application/json"}],
    io:format("DEBUG: Sending DELETE request to URL: ~p~n", [URL]),
    case httpc:request(delete, {URL, Headers}, [], []) of
        {ok, {{_, 200, _}, _, _}} ->
            io:format("DEBUG: Node ~p removed successfully from the database.~n", [NodeName]),
            ok;
        {ok, {{_, 404, _}, _, ResponseBody}} ->
            io:format("DEBUG: Node not found in the database. Response: ~p~n", [ResponseBody]),
            {error, {404, ResponseBody}};
        {ok, {{_, StatusCode, _}, _, ResponseBody}} ->
            io:format("ERROR: Failed to remove node from the database. Status: ~p, Response: ~p~n", [StatusCode, ResponseBody]),
            {error, {StatusCode, ResponseBody}};
        {error, Reason} ->
            io:format("ERROR: HTTP request failed while removing node. Reason: ~p~n", [Reason]),
            {error, Reason}
    end.

broadcast_message(_Sender, Message) ->
    case get_current_user() of
        {ok, Username} ->
            if Username =:= "admin" ->
                Nodes = [N || {N, _} <- ets:tab2list(?ACTIVE_NODES)],
                lists:foreach(
                    fun(Node) ->
                        rpc:call(Node, node_manager, handle_incoming_message, [Username, Message])
                    end, Nodes),
                io:format("Broadcasted message to all nodes.~n"),
                {ok, "Broadcast successful."};
               true ->
                io:format("Broadcast is only allowed for admin user.~n"),
                {error, "not_authorized"}
            end;
        {error, Reason} ->
            io:format("Cannot broadcast message: ~s~n", [Reason]),
            {error, Reason}
    end.

handle_incoming_message(Sender, Message) ->
    GroupLeader = whereis(user),
    io:format(GroupLeader, "DEBUG: Received message from ~p: ~p~n", [Sender, Message]),
    io:format(GroupLeader, "~p says: ~p~n", [Sender, Message]),
    ok.

synchronize_active_nodes() ->
    ConnectedNodes = nodes(),
    lists:foreach(
        fun(Node) ->
            case rpc:call(Node, node_manager, get_active_nodes, []) of
                {badrpc, _} ->
                    io:format("Failed to synchronize with ~p.~n", [Node]);
                RemoteActiveNodes ->
                    lists:foreach(fun({RemoteNode, Status}) ->
                        case ets:lookup(?ACTIVE_NODES, RemoteNode) of
                            [] ->
                                ets:insert(?ACTIVE_NODES, {RemoteNode, Status}),
                                io:format("Synchronized node ~p from ~p.~n", [RemoteNode, Node]);
                            _ ->
                                ok
                        end
                    end, RemoteActiveNodes)
            end
        end, ConnectedNodes).

get_active_nodes() ->
    ets:tab2list(?ACTIVE_NODES).

ensure_inets_started() ->
    case lists:keyfind(inets, 1, application:which_applications()) of
        {inets, _, _} -> ok;
        false -> application:start(inets)
    end.


create_group(GroupName, Members) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    URL = "http://localhost:5000/create_group",
                    Data = io_lib:format("{\"token\": \"~s\", \"group_name\": \"~s\", \"members\": ~s}",
                                         [Token, GroupName, io_lib:print(Members)]),
                    Headers = [{"Content-Type", "application/json"}],
                    http_request(post, URL, Headers, Data);
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} -> {error, Reason}
    end.


add_user_to_group(GroupName, UserToAdd) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    URL = "http://localhost:5000/add_user_to_group",
                    Data = io_lib:format("{\"token\": \"~s\", \"group_name\": \"~s\", \"username\": \"~s\"}",
                                         [Token, GroupName, UserToAdd]),
                    Headers = [{"Content-Type", "application/json"}],
                    http_request(post, URL, Headers, Data);
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} -> {error, Reason}
    end.


send_group_message(GroupName, Message) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    URL = "http://localhost:5000/group_message",
                    Data = io_lib:format("{\"token\": \"~s\", \"group_name\": \"~s\", \"message\": \"~s\"}",
                                         [Token, GroupName, Message]),
                    Headers = [{"Content-Type", "application/json"}],
                    http_request(post, URL, Headers, Data);
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} -> {error, Reason}
    end.


get_group_messages(GroupName) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    URL = "http://localhost:5000/get_group_messages?token=" ++ Token ++ "&group_name=" ++ GroupName,
                    Headers = [{"Accept", "application/json"}],
                    case httpc:request(get, {URL, Headers}, [], []) of
                        {ok, {{_, 200, _}, _, Body}} ->
                            io:format("Group messages retrieved successfully: ~s~n", [Body]),
                            {ok, Body};
                        {ok, {{_, Code, _}, _, Body}} when Code =:= 400; Code =:= 401; Code =:=403 ->
                            io:format("Failed to retrieve group messages: ~s~n", [Body]),
                            {error, Body};
                        {ok, {{_, 500, _}, _, Body}} ->
                            io:format("Server error retrieving group messages: ~s~n", [Body]),
                            {error, Body};
                        {error, Reason} ->
                            io:format("HTTP request failed while retrieving group messages: ~p~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} -> {error, Reason}
            end;
        {error, Reason} -> {error, Reason}
    end.


http_request(Method, URL, Headers, Data) ->
    ensure_inets_started(),
    case httpc:request(Method, {URL, Headers, "application/json", Data}, [], []) of
        {ok, {{_, 200, _}, _, Body}} ->
            io:format("Request successful: ~s~n", [Body]),
            {ok, Body};
        {ok, {{_, 201, _}, _, Body}} ->
            io:format("Resource created: ~s~n", [Body]),
            {ok, Body};
        {ok, {{_, Code, _}, _, Body}} when Code =:= 400; Code =:= 401; Code =:=403 ->
            io:format("Failed request (~p): ~s~n", [Code, Body]),
            {error, Body};
        {ok, {{_, 500, _}, _, Body}} ->
            io:format("Server error (~p): ~s~n", [500, Body]),
            {error, Body};
        {error, Reason} ->
            io:format("HTTP request failed: ~p~n", [Reason]),
            {error, Reason}
    end.