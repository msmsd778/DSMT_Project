-module(node_manager).
-export([init/0, broadcast_message/1, propagate_registration/1, handle_incoming_message/2,
         register_user/2, login_user/2, send_message/2, get_messages/1, create_group/2,
         delete_group/1, add_user_to_group/2, send_group_message/2, delete_message/2,
         stop_node/0, logout_user/2, delete_group_message/2, fetch_and_display_group_messages/1,
         remove_user_from_group/2, replace_session/2, refresh_token/0, get_group_messages/1,
         get_chat_partners/0, get_user_groups/0, get_user_status/1, handle_logout/1,
         upload_profile_picture/0, get_profile_picture/1, handle_group_deletion/1,
         get_current_user_token/0]).

-define(ACTIVE_NODES, active_nodes).
-define(ACTIVE_USERS, active_users).
-define(ACTIVE_SESSIONS, active_sessions).
-define(CURRENT_SESSION, current_session).

%% Initialize the Node Manager
init() ->
    code:add_patha("C:/Users/padidar/Documents/DSMT Project/backend/deps/jsx/ebin"),
    ensure_inets_started(),
    ensure_ets_table(?ACTIVE_NODES, [named_table, set, public], true),
    ensure_ets_table(?ACTIVE_USERS, [named_table, set, public], true),
    ensure_ets_table(?ACTIVE_SESSIONS, [named_table, set, public], true),
    ensure_ets_table(?CURRENT_SESSION, [named_table, set, public], true),
    
    KnownNodes = fetch_nodes_from_database(),
    lists:foreach(fun(NodeName) -> ensure_node_connection(NodeName) end, KnownNodes),
    start_node(node()).

%% Ensure ETS table exists, optionally reset
ensure_ets_table(Table, Options, Reset) when is_atom(Table), is_list(Options), is_boolean(Reset) ->
    case ets:info(Table) of
        undefined ->
            ets:new(Table, Options),
            io:format("ETS table ~p created.~n", [Table]);
        _ ->
            case Reset of
                true ->
                    ets:delete_all_objects(Table),
                    io:format("ETS table ~p reset.~n", [Table]);
                false ->
                    io:format("ETS table ~p already exists.~n", [Table])
            end
    end.

%% Register a new user
register_user(Username, Password) when is_list(Username), is_list(Password) ->
    register_user(list_to_binary(Username), list_to_binary(Password));
register_user(Username, Password) when is_binary(Username), is_binary(Password) ->
    case get_current_user() of
        {ok, ExistingUsername} ->
            io:format("Cannot register a new user while ~p is logged in. Please logout first.~n", [ExistingUsername]),
            {error, "Please logout before registering a new user."};
        {error, _Reason} ->
            ensure_inets_started(),
            URL = "http://localhost:5000/register",

            %% Construct JSON payload
            Payload = #{
                <<"username">> => Username,
                <<"password">> => Password
            },
            JSON = iolist_to_binary(jsx:encode(Payload)),

            Headers = [{"Content-Type", "application/json"}],

            %% Make HTTP POST request
            case http_request(post, URL, Headers, JSON) of
                {ok, Body} ->
                    %% Decode the response JSON
                    JsonMap = jsx:decode(Body, [return_maps]),
                    case maps:get(<<"message">>, JsonMap, undefined) of
                        undefined ->
                            io:format("Failed to parse response from server.~n"),
                            {error, "Unexpected response from server."};
                        SuccessMessage ->
                            io:format("~s~n", [SuccessMessage]),
                            {ok, SuccessMessage}
                    end;
                {error, Reason} ->
                    io:format("HTTP request failed while registering user ~s: ~p~n", [Username, Reason]),
                    {error, Reason}
            end
    
    end.

refresh_token_loop() ->
    %% Wait for 1 minutes before the first refresh
    timer:sleep(1 * 60 * 1000), %% 1 minutes
    case refresh_token() of
        {ok, _NewToken} ->
            refresh_token_loop();
        {error, Reason} ->
            io:format("Failed to refresh token: ~s~n", [Reason]),
            %% Retry after 1 minutes even if refresh fails
            timer:sleep(1 * 60 * 1000),
            refresh_token_loop()
    end.



%% Terminate the refresh_token_loop process for a given user
terminate_refresh_loop(Username) when is_binary(Username) ->
    case ets:lookup(?ACTIVE_SESSIONS, Username) of
        [{Username, _Token, RefreshPid}] when is_pid(RefreshPid) ->
            exit(RefreshPid, kill),
            io:format("Token refresh loop terminated for user ~s.~n", [binary_to_list(Username)]),
            ok;
        [{Username, _Token, _RefreshPid}] ->
            io:format("No valid RefreshPid for user ~s.~n", [binary_to_list(Username)]),
            ok;
        _ ->
            ok
    end.


%% Refresh the current user's token
%% refresh_token() -> {ok, NewToken} | {error, Reason}
refresh_token() ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct JSON payload
                    Payload = #{
                        <<"token">> => Token
                    },
                    JSON = jsx:encode(Payload),
                    Headers = [{"Content-Type", "application/json"}],
                    URL = "http://localhost:5000/refresh_token",
                    
                    %% Make HTTP POST request without binary_to_list
                    case http_request(post, URL, Headers, JSON) of
                        {ok, Body} ->
                            %% Decode JSON response with return_maps option
                            JsonMap = jsx:decode(Body, [return_maps]),
                            case maps:get(<<"token">>, JsonMap, undefined) of
                                undefined ->
                                    io:format("Failed to refresh token: ~s~n", [binary_to_list(Body)]),
                                    {error, "Failed to refresh token."};
                                NewToken ->
                                    %% Update ETS with the new token
                                    replace_session(Username, NewToken),
                                    io:format("Token refreshed successfully. New token: ~s~n", [binary_to_list(NewToken)]),
                                    {ok, NewToken}
                            end;
                        {error, Reason} ->
                            io:format("Failed to refresh token: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot refresh token: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot refresh token: ~s~n", [Reason]),
            {error, Reason}
    end.


replace_session(Username, NewToken) when is_binary(Username), is_binary(NewToken) ->
    case ets:lookup(?ACTIVE_SESSIONS, Username) of
        [{Username, _OldToken, _OldPid}] ->
            %% Just update the token; no refresh loop needed
            ets:insert(?ACTIVE_SESSIONS, {Username, NewToken, undefined}),
            ets:delete(?CURRENT_SESSION, <<"current_user">>),
            ets:insert(?CURRENT_SESSION, {<<"current_user">>, Username}),
            io:format("Session token replaced for user ~s.~n", [binary_to_list(Username)]),
            ok;
        _ ->
            io:format("Failed to replace session token for user ~s: Invalid session data.~n",
                      [binary_to_list(Username)]),
            {error, "Invalid session data."}
    end.


login_user(Username, Password) when is_list(Username), is_list(Password) ->
    BinaryUsername = list_to_binary(Username),
    BinaryPassword = list_to_binary(Password),
    NodeName = list_to_binary(atom_to_list(node())),
    case get_current_user() of
        {ok, ExistingUser} ->
            {error, "A user is already logged in. Please logout first."};
        {error, _Reason} ->
            ensure_inets_started(),
            URL = "http://localhost:5000/login",
            Payload = #{
                <<"username">> => BinaryUsername,
                <<"password">> => BinaryPassword,
                <<"node_name">> => NodeName
            },
            JSON = iolist_to_binary(jsx:encode(Payload)),
            Headers = [{"Content-Type", "application/json"}],

            case http_request(post, URL, Headers, JSON) of
                {ok, Body} ->
                    JsonMap = jsx:decode(Body, [return_maps]),
                    Token = maps:get(<<"token">>, JsonMap, undefined),
                    if
                        Token =/= undefined ->
                            io:format("Login successful for user ~s.~n", [binary_to_list(BinaryUsername)]),
                            %% **NEW: Remove existing session before inserting a new one**
                            ets:delete_all_objects(?ACTIVE_SESSIONS),
                            %% Insert the new session
                            ets:insert(?ACTIVE_SESSIONS, {BinaryUsername, Token, undefined}),
                            ets:delete_all_objects(?CURRENT_SESSION),
                            ets:insert(?CURRENT_SESSION, {<<"current_user">>, BinaryUsername}),
                            io:format("Current user set to ~s after login.~n", [binary_to_list(BinaryUsername)]),
                            {ok, Token};
                        true ->
                            io:format("Token not found in response for user ~s.~n", [binary_to_list(BinaryUsername)]),
                            {error, "Invalid response from server."}
                    end;
                {error, Reason} ->
                    io:format("HTTP request failed while logging in user ~s: ~p~n",
                              [binary_to_list(BinaryUsername), Reason]),
                    {error, Reason}
            end
    end.


%% Make the 0-arg logout_user() just call the 2-arg version with the correct token
logout_user(Username, Token) when is_list(Username), is_list(Token) ->
    logout_user(list_to_binary(Username), list_to_binary(Token));
logout_user(Username, Token) when is_binary(Username), is_binary(Token) ->
    io:format("logout_user/2 called for ~p with token ~p~n", [Username, Token]),

    %% 1) Check if ETS sees that user (with correct or mismatched token)
    case ets:lookup(?ACTIVE_SESSIONS, Username) of
        [{Username, TokenStored, RefreshPid}] ->
            if TokenStored =/= Token ->
                io:format("Provided token ~s doesn't match stored ~s. Force-logout anyway.~n",
                          [binary_to_list(Token), binary_to_list(TokenStored)]);
               true ->
                ok
            end,
            terminate_refresh_loop(Username),
            ets:delete(?ACTIVE_SESSIONS, Username),
            io:format("Removed ~p from ACTIVE_SESSIONS.~n", [Username]);

        _ ->
            io:format("No active session found in ETS for ~p.~n", [Username])
    end,

    %% 2) Clear CURRENT_SESSION if it's them
    case ets:lookup(?CURRENT_SESSION, <<"current_user">>) of
        [{<<"current_user">>, Username}] ->
            ets:delete(?CURRENT_SESSION, <<"current_user">>),
            io:format("Cleared CURRENT_SESSION for ~p.~n", [Username]);
        _ ->
            ok
    end,

    %% 3) Call Python /logout to remove DB session and set user offline
    Payload = iolist_to_binary(jsx:encode(#{<<"token">> => Token})),
    Headers = [{"Content-Type", "application/json"}],
    case http_request(post, "http://localhost:5000/logout", Headers, Payload) of
        {ok, Body} ->
            io:format("Python logout response: ~s~n", [binary_to_list(Body)]);
        {error, Reason} ->
            io:format("Failed to call Python /logout: ~p~n", [Reason])
    end,

    %% 4) Propagate logout to ALL connected nodes
    propagate_logout(Username),

    {ok, "Logout successful in Erlang."}.



%% Handle logout on remote nodes
handle_logout(Username) when is_binary(Username) ->
    case ets:lookup(?ACTIVE_SESSIONS, Username) of
        [{Username, _Token, _RefreshPid}] ->
            ets:delete(?ACTIVE_SESSIONS, Username),
            terminate_refresh_loop(Username),
            io:format("User ~s logged out remotely.~n", [binary_to_list(Username)]),
            ok;
        _ ->
            ok
    end.

%% Propagate logout to all connected nodes
propagate_logout(Username) ->
    Nodes = [N || {N, _} <- ets:tab2list(?ACTIVE_NODES), N /= node()],
    lists:foreach(
        fun(Node) ->
            case rpc:call(Node, node_manager, handle_logout, [Username]) of
                ok ->
                    io:format("Logout propagated to ~p.~n", [Node]);
                {badrpc, Reason} ->
                    io:format("Failed to propagate logout to ~p: ~p~n", [Node, Reason])
            end
        end, Nodes).

%% Retrieve the currently set user's username
get_current_user() ->
    case ets:lookup(?CURRENT_SESSION, <<"current_user">>) of
        [{<<"current_user">>, Username}] -> {ok, Username};
        [] -> {error, "Access denied: You need to login first."}
    end.

get_user_token(Username) when is_binary(Username) ->
    case ets:lookup(?ACTIVE_SESSIONS, Username) of
        [{Username, Token, _RefreshPid}] -> {ok, Token};
        [{Username, _Token}] -> {error, "Invalid session data."};
        [] -> {error, "User not logged in or token not stored"};
        _ -> {error, "Invalid session entry."}
    end.

get_current_user_token() ->
    case ets:lookup(?CURRENT_SESSION, <<"current_user">>) of
        [{<<"current_user">>, Username}] ->
            %% Look up the user's token in ACTIVE_SESSIONS
            case ets:lookup(?ACTIVE_SESSIONS, Username) of
                [{Username, Token, _RefreshPid}] ->
                    {ok, Token};
                _ ->
                    {error, "No active session found for the current user."}
            end;
        [] ->
            {error, "No user is currently logged in."}
    end.

%% Retrieve the status of a specific user
%% get_user_status(User) -> {ok, StatusInfo} | {error, Reason}
get_user_status(User) when is_list(User) ->
    get_user_status(list_to_binary(User));
get_user_status(User) when is_binary(User) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct query parameters
                    QParams = <<"token=", Token/binary, "&username=", User/binary>>,
                    URL = <<"http://localhost:5000/get_user_status?", QParams/binary>>,
                    Headers = [{"Accept", "application/json"}],
                    
                    %% Make HTTP GET request
                    case http_request(get, binary_to_list(URL), Headers, "") of
                        {ok, Body} ->
                            %% Decode JSON response
                            try
                                JsonMap = jsx:decode(Body, [return_maps]),
                                case maps:get(<<"status">>, JsonMap, undefined) of
                                    undefined ->
                                        io:format("Failed to retrieve user status: ~s~n", [binary_to_list(Body)]),
                                        {error, "Failed to retrieve user status."};
                                    Status ->
                                        case maps:get(<<"last_online">>, JsonMap, undefined) of
                                            undefined ->
                                                io:format("User ~s is ~s.~n", [binary_to_list(User), Status]),
                                                {ok, #{status => Status}};
                                            LastOnline ->
                                                io:format("User ~s is ~s. Last online at ~s.~n", 
                                                          [binary_to_list(User), Status, binary_to_list(LastOnline)]),
                                                {ok, #{status => Status, last_online => LastOnline}}
                                        end
                                end
                            catch
                                _: _Reason ->
                                    io:format("Failed to parse JSON response: ~s~n", [binary_to_list(Body)]),
                                    {error, "Invalid response from server."}
                            end;
                        {error, Reason} ->
                            io:format("Failed to retrieve user status: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot retrieve user status: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot retrieve user status: ~s~n", [Reason]),
            {error, Reason}
    end.


%% Send a one-to-one message
send_message(Receiver, Message) when is_list(Receiver), is_list(Message) ->
    send_message(list_to_binary(Receiver), list_to_binary(Message));
send_message(Receiver, Message) when is_binary(Receiver), is_binary(Message) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct JSON payload using jsx and convert to binary
                    Payload = #{
                        <<"token">> => Token,
                        <<"receiver">> => Receiver,
                        <<"message">> => Message
                    },
                    JSON = iolist_to_binary(jsx:encode(Payload)),
                    
                    URL = "http://localhost:5000/send_message",
                    Headers = [{"Content-Type", "application/json"}],
                    
                    %% Make HTTP POST request
                    case http_request(post, URL, Headers, JSON) of
                        {ok, Body} ->
                            %% Decode JSON response
                            JsonMap = jsx:decode(Body),
                            case maps:get(<<"message">>, JsonMap, undefined) of
                                undefined ->
                                    io:format("Failed to send message: ~s~n", [binary_to_list(Body)]),
                                    {error, "Failed to send message."};
                                SentMessage ->
                                    io:format("Message sent successfully: ~s~n", [binary_to_list(SentMessage)]),
                                    {ok, SentMessage}
                            end;
                        {error, Reason} ->
                            io:format("Failed to send message: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot send message: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot send message: ~s~n", [Reason]),
            {error, Reason}
    end.


%% Process individual one-to-one message for display (for erlang shells)
process_one_to_one_message(Msg, _CurrentUser) ->
    Sender    = maps:get(<<"sender">>,   Msg, <<"">>),
    Receiver  = maps:get(<<"receiver">>, Msg, <<"">>),
    Message   = maps:get(<<"message">>,  Msg, <<"">>),
    Timestamp = maps:get(<<"timestamp">>,Msg, <<"">>),

    %% Return only the essential fields
    #{
      <<"sender">>    => Sender,
      <<"receiver">>  => Receiver,
      <<"message">>   => Message,
      <<"timestamp">> => Timestamp
    }.


%% Fetch messages between current user and another user
%% get_messages(OtherUser) -> {ok, Messages} | {error, Reason}
get_messages(OtherUser) when is_list(OtherUser) ->
    get_messages(list_to_binary(OtherUser));
get_messages(OtherUser) when is_binary(OtherUser) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    QParams = <<"token=", Token/binary, "&other_user=", OtherUser/binary>>,
                    URL = <<"http://localhost:5000/get_messages?", QParams/binary>>,
                    Headers = [{"Accept", "application/json"}],

                    %% Fetch messages via HTTP
                    case http_request(get, binary_to_list(URL), Headers, "") of
                        {ok, Body} ->
                            JsonMap = jsx:decode(Body),
                            case maps:get(<<"messages">>, JsonMap, undefined) of
                                undefined ->
                                    {error, "Failed to retrieve messages."};
                                Messages ->
                                    ProcessedMessages = lists:map(fun(Msg) ->
                                        process_one_to_one_message(Msg, Username)
                                    end, Messages),
                                    {ok, ProcessedMessages}
                            end;
                        {error, Reason} ->
                            {error, Reason}
                    end;
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.


%% Retrieve chat partners associated with the current user
%% get_chat_partners() -> {ok, Partners} | {error, Reason}
get_chat_partners() ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct query parameters
                    QParams = <<"token=", Token/binary>>,
                    URL = <<"http://localhost:5000/get_chat_partners?", QParams/binary>>,
                    Headers = [{"Accept", "application/json"}],
                    
                    %% Make HTTP GET request
                    case http_request(get, binary_to_list(URL), Headers, "") of
                        {ok, Body} ->
                            %% Decode JSON response
                            try
                                JsonMap = jsx:decode(Body, [return_maps]),
                                case maps:get(<<"chat_partners">>, JsonMap, undefined) of
                                    undefined ->
                                        io:format("Failed to retrieve chat partners: ~s~n", [binary_to_list(Body)]),
                                        {error, "Failed to retrieve chat partners."};
                                    Partners ->
                                        io:format("Chat partners: ~p~n", [Partners]),
                                        {ok, Partners}
                                end
                            catch
                                _: _Reason ->
                                    io:format("Failed to parse JSON response: ~s~n", [binary_to_list(Body)]),
                                    {error, "Invalid response from server."}
                            end;
                        {error, Reason} ->
                            io:format("Failed to retrieve chat partners: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot retrieve chat partners: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot retrieve chat partners: ~s~n", [Reason]),
            {error, Reason}
    end.


%% Get messages from a group
%% get_group_messages(GroupName) -> {ok, GroupMessages} | {error, Reason}
get_group_messages(GroupName) when is_list(GroupName) ->
    get_group_messages(list_to_binary(GroupName));
get_group_messages(GroupName) when is_binary(GroupName) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct query parameters using binary concatenation
                    QParams = << "token=", Token/binary, "&group_name=", GroupName/binary >>,
                    URL = <<"http://localhost:5000/get_group_messages?", QParams/binary>>,
                    Headers = [{"Accept", "application/json"}],
                    
                    %% Make HTTP GET request
                    case http_request(get, binary_to_list(URL), Headers, "") of
                        {ok, Body} ->
                            %% Decode JSON response
                            JsonMap = jsx:decode(Body),
                            case maps:get(<<"group_messages">>, JsonMap, undefined) of
                                undefined ->
                                    io:format("Failed to retrieve group messages: ~s~n", [binary_to_list(Body)]),
                                    {error, "Failed to retrieve group messages."};
                                GroupMessages ->
                                    %% Process group messages and display read receipts for sent messages
                                    ProcessedGroupMessages = lists:map(fun(Msg) ->
                                        process_group_message(Msg, Username)
                                    end, GroupMessages),
                                    {ok, ProcessedGroupMessages}
                            end;
                        {error, Reason} ->
                            io:format("Failed to retrieve group messages: ~p~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot retrieve group messages: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot retrieve group messages: ~s~n", [Reason]),
            {error, Reason}
    end.


%% Process individual group message for display
process_group_message(Msg, CurrentUser) ->
    Sender    = maps:get(<<"sender">>,   Msg, <<>>),
    Message   = maps:get(<<"message">>,  Msg, <<>>),
    Timestamp = maps:get(<<"timestamp">>,Msg, <<>>),
    ReadByBin = maps:get(<<"read_by">>,  Msg, []),

    %% Convert each binary in read_by to a char-list for string operations
    ReadByLists = [ binary_to_list(BinUser) || BinUser <- ReadByBin ],

    %% Determine if the current user sent this message
    Sent = (Sender =:= CurrentUser),

    %% If sent by current user, show read receipts
    ReadStatus =
      case Sent of
        true ->
            case ReadByLists of
                [] -> "Not Read by any members";
                _  -> "Read by: " ++ string:join(ReadByLists, ", ")
            end;
        false ->
            ""
      end,

    %% Return processed message as a map
    #{
      <<"sender">>     => Sender,
      <<"message">>    => Message,
      <<"timestamp">>  => Timestamp,
      <<"sent">>       => Sent,
      <<"read_status">> => ReadStatus
    }.

    
%% Display group messages with read receipts and timestamp
display_group_messages(GroupMessages) ->
    lists:foreach(fun(Msg) ->
        Sender = maps:get(<<"sender">>, Msg, ""),
        Message = maps:get(<<"message">>, Msg, ""),
        Timestamp = maps:get(<<"timestamp">>, Msg, ""),
        Sent = maps:get(<<"sent">>, Msg, false),
        ReadStatus = maps:get(<<"read_status">>, Msg, ""),
        
        %% Format message display with timestamp
        Display = if
            Sent ->
                "[Sent] " ++ Message ++ " (" ++ ReadStatus ++ ") at " ++ Timestamp;
            true ->
                "[" ++ Sender ++ "] " ++ Message ++ " at " ++ Timestamp
        end,
        
        io:format("~s~n", [Display])
    end, GroupMessages).


%% Fetch and display group messages
fetch_and_display_group_messages(GroupName) when is_binary(GroupName) ->
    case get_group_messages(GroupName) of
        {ok, GroupMessages} ->
            display_group_messages(GroupMessages),
            ok;
        {error, Reason} ->
            io:format("Error fetching group messages: ~s~n", [Reason]),
            {error, Reason}
    end.

%% Create a group
%% create_group(GroupName, Members) -> {ok, Body} | {error, Reason}
create_group(GroupName, Members) when is_list(GroupName), is_list(Members) ->
    create_group(list_to_binary(GroupName), Members);
create_group(GroupName, Members) when is_binary(GroupName), is_list(Members) ->
    %% Convert each member from list to binary if they are not already binaries
    BinaryMembers = [ 
        case Member of
            Bin when is_binary(Bin) -> Bin;
            List when is_list(List) -> list_to_binary(List)
        end 
        || Member <- Members 
    ],
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct JSON payload using jsx
                    Payload = #{
                        <<"token">> => Token,
                        <<"group_name">> => GroupName,
                        <<"members">> => BinaryMembers
                    },
                    JSON = jsx:encode(Payload),
                    
                    URL = "http://localhost:5000/create_group",
                    Headers = [{"Content-Type", "application/json"}],
                    
                    %% Make HTTP POST request
                    case http_request(post, URL, Headers, JSON) of
                        {ok, Body} ->
                            %% Decode JSON response
                            try
                                JsonMap = jsx:decode(Body, [return_maps]),
                                case maps:get(<<"message">>, JsonMap, undefined) of
                                    undefined ->
                                        io:format("Failed to create group: ~s~n", [binary_to_list(Body)]),
                                        {error, "Failed to create group."};
                                    Message ->
                                        io:format("Create group response: ~s~n", [Message]),
                                        {ok, Message}
                                end
                            catch
                                _: _Reason ->
                                    io:format("Failed to parse JSON response: ~s~n", [binary_to_list(Body)]),
                                    {error, "Invalid response from server."}
                            end;
                        {error, Reason} ->
                            io:format("Failed to create group: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot create group: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot create group: ~s~n", [Reason]),
            {error, Reason}
    end.


%% Delete a group (Owner Only)
delete_group(GroupName) when is_list(GroupName) ->
    delete_group(list_to_binary(GroupName));
delete_group(GroupName) when is_binary(GroupName) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct JSON payload
                    Payload = #{
                        <<"token">> => Token,
                        <<"group_name">> => GroupName
                    },
                    JSON = jsx:encode(Payload),
                    
                    URL = "http://localhost:5000/delete_group",
                    Headers = [{"Content-Type", "application/json"}],
                    
                    %% Make HTTP DELETE request
                    case http_request(delete, URL, Headers, JSON) of
                        {ok, Body} ->
                            %% Decode JSON response
                            try
                                JsonMap = jsx:decode(Body, [return_maps]),
                                case maps:get(<<"message">>, JsonMap, undefined) of
                                    undefined ->
                                        io:format("Failed to delete group: ~s~n", [binary_to_list(Body)]),
                                        {error, "Failed to delete group."};
                                    Message ->
                                        io:format("Delete group response: ~s~n", [Message]),
                                        %% Propagate deletion to other nodes
                                        propagate_group_deletion(GroupName),
                                        {ok, Message}
                                end
                            catch
                                _: _Reason ->
                                    io:format("Failed to parse JSON response: ~s~n", [binary_to_list(Body)]),
                                    {error, "Invalid response from server."}
                            end;
                        {error, Reason} ->
                            io:format("Failed to delete group: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot delete group: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot delete group: ~s~n", [Reason]),
            {error, Reason}
    end.

%% Propagate group deletion to all connected nodes
propagate_group_deletion(GroupName) when is_binary(GroupName) ->
    Nodes = [N || {N, _} <- ets:tab2list(?ACTIVE_NODES), N /= node()],
    lists:foreach(
        fun(Node) ->
            case rpc:call(Node, node_manager, handle_group_deletion, [GroupName]) of
                ok ->
                    io:format("Group deletion propagated to ~p.~n", [Node]);
                {badrpc, Reason} ->
                    io:format("Failed to propagate group deletion to ~p: ~p~n", [Node, Reason])
            end
        end, Nodes).

%% Handle incoming group deletion from another node
handle_group_deletion(GroupName) when is_binary(GroupName) ->
    %% Remove group-related data if stored locally
    %% Example: remove from ETS if groups are stored
    %% ets:delete(?GROUPS, GroupName),
    io:format("Group ~s has been deleted from the system.~n", [binary_to_list(GroupName)]),
    %% Optionally, delete any cached messages or perform additional cleanup
    ok.


%% Retrieve groups associated with the current user
%% get_user_groups() -> {ok, Groups} | {error, Reason}
get_user_groups() ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct query parameters
                    QParams = <<"token=", Token/binary>>,
                    URL = <<"http://localhost:5000/get_user_groups?", QParams/binary>>,
                    Headers = [{"Accept", "application/json"}],
                    
                    %% Make HTTP GET request
                    case http_request(get, binary_to_list(URL), Headers, "") of
                        {ok, Body} ->
                            %% Decode JSON response
                            try
                                JsonMap = jsx:decode(Body, [return_maps]),
                                case maps:get(<<"group_names">>, JsonMap, undefined) of
                                    undefined ->
                                        io:format("Failed to retrieve user groups: ~s~n", [Body]),
                                        {error, "Failed to retrieve user groups."};
                                    Groups ->
                                        io:format("User groups: ~p~n", [Groups]),
                                        {ok, Groups}
                                end
                            catch
                                _: _Reason ->
                                    io:format("Failed to parse JSON response: ~s~n", [binary_to_list(Body)]),
                                    {error, "Invalid response from server."}
                            end;
                        {error, Reason} ->
                            io:format("Failed to retrieve user groups: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot retrieve user groups: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot retrieve user groups: ~s~n", [Reason]),
            {error, Reason}
    end.


%% Add a user to a group
%% add_user_to_group(GroupName, UsernameToAdd) -> {ok, Body} | {error, Reason}
add_user_to_group(GroupName, UsernameToAdd) when is_binary(GroupName), is_binary(UsernameToAdd) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct JSON payload using jsx
                    Payload = #{
                        <<"token">> => Token,
                        <<"group_name">> => GroupName,
                        <<"username">> => UsernameToAdd
                    },
                    JSON = jsx:encode(Payload),
                    
                    URL = "http://localhost:5000/add_user_to_group",
                    Headers = [{"Content-Type", "application/json"}],
                    
                    %% Make HTTP POST request
                    case http_request(post, URL, Headers, JSON) of
                        {ok, Body} ->
                            %% Decode JSON response
                            {ok, JsonMap} = jsx:decode(Body),
                            case maps:get(<<"message">>, JsonMap, undefined) of
                                undefined ->
                                    io:format("Failed to add user to group: ~s~n", [Body]),
                                    {error, "Failed to add user to group."};
                                Message ->
                                    io:format("Add user to group response: ~s~n", [Message]),
                                    {ok, Message}
                            end;
                        {error, Reason} ->
                            io:format("Failed to add user to group: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot add user to group: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot add user to group: ~s~n", [Reason]),
            {error, Reason}
    end.

%% Remove a user from a group (Owner Only)
%% remove_user_from_group(GroupName, UsernameToRemove) -> {ok, Body} | {error, Reason}
remove_user_from_group(GroupName, UsernameToRemove) when is_binary(GroupName), is_binary(UsernameToRemove) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct JSON payload using jsx
                    Payload = #{
                        <<"token">> => Token,
                        <<"group_name">> => GroupName,
                        <<"username">> => UsernameToRemove
                    },
                    JSON = jsx:encode(Payload),
                    
                    URL = "http://localhost:5000/remove_user_from_group",
                    Headers = [{"Content-Type", "application/json"}],
                    
                    %% Make HTTP POST request
                    case http_request(post, URL, Headers, JSON) of
                        {ok, Body} ->
                            %% Decode JSON response
                            {ok, JsonMap} = jsx:decode(Body),
                            case maps:get(<<"message">>, JsonMap, undefined) of
                                undefined ->
                                    io:format("Failed to remove user from group: ~s~n", [Body]),
                                    {error, "Failed to remove user from group."};
                                Message ->
                                    io:format("Remove user from group response: ~s~n", [Message]),
                                    {ok, Message}
                            end;
                        {error, Reason} ->
                            io:format("Failed to remove user from group: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot remove user from group: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot remove user from group: ~s~n", [Reason]),
            {error, Reason}
    end.

%% Send a group message
send_group_message(GroupName, Message) when is_list(GroupName), is_list(Message) ->
    send_group_message(list_to_binary(GroupName), list_to_binary(Message));
send_group_message(GroupName, Message) when is_binary(GroupName), is_binary(Message) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct JSON payload using jsx and convert to binary
                    Payload = #{
                        <<"token">> => Token,
                        <<"group_name">> => GroupName,
                        <<"message">> => Message
                    },
                    JSON = iolist_to_binary(jsx:encode(Payload)),
                    
                    URL = "http://localhost:5000/send_group_message",
                    Headers = [{"Content-Type", "application/json"}],
                    
                    %% Make HTTP POST request
                    case http_request(post, URL, Headers, JSON) of
                        {ok, Body} ->
                            %% Decode JSON response
                            JsonMap = jsx:decode(Body),
                            case maps:get(<<"message">>, JsonMap, undefined) of
                                undefined ->
                                    io:format("Failed to send group message: ~s~n", [binary_to_list(Body)]),
                                    {error, "Failed to send group message."};
                                SentMessage ->
                                    io:format("Group message sent successfully: ~s~n", [binary_to_list(SentMessage)]),
                                    {ok, SentMessage}
                            end;
                        {error, Reason} ->
                            io:format("Failed to send group message: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot send group message: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot send group message: ~s~n", [Reason]),
            {error, Reason}
    end.


%% Delete a message
%% delete_message(MessageID, DeleteForBoth) -> {ok, Body} | {error, Reason}
delete_message(MessageID, DeleteForBoth) when is_binary(MessageID), is_boolean(DeleteForBoth) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct JSON payload using jsx
                    Payload = #{
                        <<"token">> => Token,
                        <<"message_id">> => MessageID,
                        <<"delete_for_both">> => DeleteForBoth
                    },
                    JSON = jsx:encode(Payload),
                    
                    URL = "http://localhost:5000/delete_message",
                    Headers = [{"Content-Type", "application/json"}],
                    
                    %% Make HTTP POST request
                    case http_request(post, URL, Headers, JSON) of
                        {ok, Body} ->
                            %% Decode JSON response
                            {ok, JsonMap} = jsx:decode(Body),
                            case maps:get(<<"message">>, JsonMap, undefined) of
                                undefined ->
                                    io:format("Failed to delete message: ~s~n", [Body]),
                                    {error, "Failed to delete message."};
                                Message ->
                                    io:format("Delete message response: ~s~n", [Message]),
                                    {ok, Message}
                            end;
                        {error, Reason} ->
                            io:format("Failed to delete message: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot delete message: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot delete message: ~s~n", [Reason]),
            {error, Reason}
    end.

%% Delete a group message
%% delete_group_message(GroupName, MessageID) -> {ok, Body} | {error, Reason}
delete_group_message(GroupName, MessageID) when is_binary(GroupName), is_binary(MessageID) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    %% Construct JSON payload using jsx
                    Payload = #{
                        <<"token">> => Token,
                        <<"group_name">> => GroupName,
                        <<"message_id">> => MessageID
                    },
                    JSON = jsx:encode(Payload),
                    
                    URL = "http://localhost:5000/delete_group_message",
                    Headers = [{"Content-Type", "application/json"}],
                    
                    %% Make HTTP POST request
                    case http_request(post, URL, Headers, JSON) of
                        {ok, Body} ->
                            %% Decode JSON response
                            {ok, JsonMap} = jsx:decode(Body),
                            case maps:get(<<"message">>, JsonMap, undefined) of
                                undefined ->
                                    io:format("Failed to delete group message: ~s~n", [Body]),
                                    {error, "Failed to delete group message."};
                                Message ->
                                    io:format("Delete group message response: ~s~n", [Message]),
                                    {ok, Message}
                            end;
                        {error, Reason} ->
                            io:format("Failed to delete group message: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot delete group message: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot delete group message: ~s~n", [Reason]),
            {error, Reason}
    end.


%% Fetch nodes from the database
fetch_nodes_from_database() ->
    URL = "http://localhost:5000/get_active_nodes",
    Headers = [{"Accept", "application/json"}],
    io:format("DEBUG: Sending GET request to URL: ~s~n", [URL]),
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

%% Extract nodes from JSON response
extract_nodes(JSON) when is_binary(JSON) ->
    %% Correctly decode JSON without expecting a tuple
    JsonMap = jsx:decode(JSON),
    Nodes = case maps:get(<<"nodes">>, JsonMap, undefined) of
        undefined -> [];
        NodeList when is_list(NodeList) ->
            [ maps:get(<<"node_name">>, Node, "") || Node <- NodeList ]
    end,
    io:format("Extracted Nodes: ~p~n", [Nodes]),
    Nodes;
extract_nodes(JSON) when is_list(JSON) ->
    BinaryJSON = list_to_binary(JSON),
    extract_nodes(BinaryJSON).


ensure_node_connection(Node) when is_binary(Node) ->
    try
        NodeAtom = binary_to_atom(Node, utf8),
        case net_adm:ping(NodeAtom) of
            pong ->
                io:format("Successfully connected to ~p.~n", [NodeAtom]);
            pang ->
                io:format("Failed to connect to ~p.~n", [NodeAtom])
        end
    catch
        error:badarg ->
            io:format("Invalid node name: ~s~n", [binary_to_list(Node)]),
            {error, invalid_node_name}
    end.


start_node(NodeName) when is_atom(NodeName) ->
    net_kernel:start([NodeName, shortnames]),
    register_node(NodeName).


%% Register a node locally and update the database
register_node(Node) when is_atom(Node) ->
    case ets:lookup(?ACTIVE_NODES, Node) of
        [] ->
            ets:insert(?ACTIVE_NODES, {Node, connected}),
            io:format("Node ~p registered locally.~n", [Node]),
            update_node_in_database(Node, connected);
        _ ->
            io:format("Node ~p is already registered locally.~n", [Node])
    end,
    %% Notify all connected nodes about the new node
    lists:foreach(
        fun(ConnectedNode) ->
            rpc:call(ConnectedNode, node_manager, propagate_registration, [Node])
        end, nodes()).

%% Update node status in the database
update_node_in_database(Node, Status) when is_atom(Node), is_atom(Status) ->
    ensure_inets_started(),
    URL = "http://localhost:5000/register_node",
    
    %% Construct JSON payload using jsx
    Payload = #{
        <<"node_name">> => list_to_binary(atom_to_list(Node)),
        <<"status">> => list_to_binary(atom_to_list(Status))
    },
    JSON = jsx:encode(Payload),
    
    case httpc:request(post, {URL, [], "application/json", JSON}, [], []) of
        {ok, {{_, 200, _}, _, _}} ->
            io:format("Node ~p updated in the database successfully.~n", [Node]);
        {ok, {{_, StatusCode, _}, _, ResponseBody}} ->
            io:format("Failed to update node ~p. Status: ~p, Response: ~p~n", [Node, StatusCode, ResponseBody]);
        {error, Reason} ->
            io:format("Failed to update node ~p in the database: ~p~n", [Node, Reason]),
            {error, Reason}
    end.

%% Propagate node registration to remote nodes
propagate_registration(Node) when is_atom(Node) ->
    case ets:lookup(?ACTIVE_NODES, Node) of
        [] ->
            ets:insert(?ACTIVE_NODES, {Node, connected}),
            io:format("Node ~p registered remotely.~n", [Node]);
        _ ->
            io:format("Node ~p is already registered remotely.~n", [Node])
    end.


%% Stop the node, unregister it locally, and remove it from the database
stop_node() ->
    Node = node(),

    %% Unregister locally
    case ets:lookup(?ACTIVE_NODES, Node) of
        [{Node, _}] ->
            ets:delete(?ACTIVE_NODES, Node),
            io:format("Node ~p unregistered locally.~n", [Node]);
        [] ->
            io:format("Node ~p not found in active_nodes, skipping local removal.~n", [Node])
    end,

    %% Remove from database
    DatabaseResult = 
        case remove_node_from_database(Node) of
            ok ->
                io:format("Node ~p removed from the database successfully.~n", [Node]),
                ok;
            {error, {404, _}} ->
                io:format("Node ~p not found in the database, skipping database removal.~n", [Node]),
                ok;
            {error, DbReason} -> %% Use a distinct variable
                io:format("Failed to remove node ~p from the database: ~p~n", [Node, DbReason]),
                {error, DbReason}
        end,

    %% Stop the node
    StopResult = 
        case net_kernel:stop() of
            ok ->
                io:format("Node ~p stopped successfully.~n", [Node]),
                ok;
            {error, StopReason} -> %% Use another distinct variable
                io:format("Failed to stop node ~p: ~p~n", [Node, StopReason]),
                {error, StopReason}
        end,

    %% Return the result of the operation
    case {DatabaseResult, StopResult} of
        {ok, ok} ->
            ok;
        _ ->
            {error, {database_result, DatabaseResult, stop_result, StopResult}}
    end.



%% Remove a node from the database
remove_node_from_database(Node) when is_atom(Node) ->
    ensure_inets_started(),
    NodeName = atom_to_list(Node),
    EncodedNodeName = uri_string:encode(NodeName),
    URL = "http://localhost:5000/remove_node/" ++ EncodedNodeName,
    Headers = [{"Content-Type", "application/json"}],
    io:format("DEBUG: Sending DELETE request to URL: ~s~n", [URL]),
    case http_request(delete, URL, Headers, "") of
        {ok, {{_, 200, _}, _, _}} ->
            io:format("DEBUG: Node ~s removed successfully from the database.~n", [NodeName]),
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


%% Broadcast a message to all nodes (admin only)
broadcast_message(Message) when is_list(Message) ->
    broadcast_message(list_to_binary(Message));
broadcast_message(Message) when is_binary(Message) ->
    case get_current_user() of
        {ok, Username} ->
            if
                Username =:= <<"admin">> ->
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


%% Handle incoming message from another node
handle_incoming_message(Sender, Message) when is_binary(Sender), is_binary(Message) ->
    GroupLeader = whereis(user),
    io:format(GroupLeader, "DEBUG: Received message from ~s: ~s~n", [Sender, Message]),
    io:format(GroupLeader, "~s says: ~s~n", [Sender, Message]),
    ok.


%% Ensure inets application is started
ensure_inets_started() ->
    case lists:keyfind(inets, 1, application:which_applications()) of
        {inets, _, _} -> ok;
        false -> application:start(inets)
    end.

%% Helper function to make HTTP requests
http_request(Method, URL, Headers, Data) when is_atom(Method), is_list(URL), is_list(Headers) ->
    ensure_inets_started(),
    %% Ensure Data is binary
    BinaryData = case Data of
        "" -> <<"">>;
        _ -> iolist_to_binary(Data)
    end,
    Request =
        case Method of
            get ->
                {URL, Headers};
            post ->
                {URL, Headers, "application/json", BinaryData};
            put ->
                {URL, Headers, "application/json", BinaryData};
            delete ->
                {URL, Headers, "application/json", BinaryData};
            _ ->
                {URL, Headers, "application/json", BinaryData}
        end,
    Options = [],
    case httpc:request(Method, Request, Options, []) of
        {ok, {{_, 200, _}, _, Body}} ->
            BinaryBody = convert_to_binary(Body),
            io:format("Request successful: ~s~n", [binary_to_list(BinaryBody)]),
            {ok, BinaryBody};
        {ok, {{_, 201, _}, _, Body}} ->
            BinaryBody = convert_to_binary(Body),
            io:format("Resource created: ~s~n", [binary_to_list(BinaryBody)]),
            {ok, BinaryBody};
        {ok, {{_, Code, _}, _, Body}} when Code == 400 orelse Code == 401 orelse Code == 403 ->
            BinaryBody = convert_to_binary(Body),
            %% Decode JSON error response
            case jsx:decode(BinaryBody) of
                JsonMap when is_map(JsonMap) ->
                    ErrorMsg = maps:get(<<"error">>, JsonMap, <<"Unknown error.">>),
                    io:format("Failed request (~p): ~s~n", [Code, binary_to_list(ErrorMsg)]),
                    {error, ErrorMsg};
                _ ->
                    io:format("Failed request (~p): ~s~n", [Code, binary_to_list(BinaryBody)]),
                    {error, "Failed request."}
            end;
        {ok, {{_, 500, _}, _, Body}} ->
            BinaryBody = convert_to_binary(Body),
            io:format("Server error (~p): ~s~n", [500, binary_to_list(BinaryBody)]),
            {error, "Server error."};
        {error, Reason} ->
            io:format("HTTP request failed: ~p~n", [Reason]),
            {error, Reason}
    end.

%% Helper function to convert response body to binary if it's a list
convert_to_binary(Body) when is_binary(Body) ->
    Body;
convert_to_binary(Body) when is_list(Body) ->
    list_to_binary(Body).

%% Upload Profile Picture
upload_profile_picture() ->
    %% Retrieve the current user's token
    case get_current_user_token() of
        {ok, Token} ->
            %% Call the Python script to get the Base64 image string
            Command = "python upload_image_gui.py",
            case os:cmd(Command) of
                "" ->
                    io:format("No file selected or error occurred.~n"),
                    {error, "No file selected"};
                Base64Image ->
                    %% Clean up the Base64 string
                    Base64Cleaned = string:trim(Base64Image),
                    %% Convert list to binary
                    Base64CleanedBinary = list_to_binary(Base64Cleaned),
                    %% Debug: Print the Base64 string
                    io:format("Base64 Cleaned Binary: ~s~n", [Base64CleanedBinary]),
                    set_profile_picture(Token, Base64CleanedBinary)
            end;
        {error, Reason} ->
            io:format("Failed to retrieve current user's token: ~s~n", [Reason]),
            {error, Reason}
    end.

set_profile_picture(Token, Base64Image) ->
    URL = "http://localhost:5000/set_profile_picture",
    %% Encode the payload as JSON
    PayloadMap = #{
        <<"token">> => Token,
        <<"image_data">> => Base64Image
    },
    Payload = jsx:encode(PayloadMap),
    
    %% Debug: Print the JSON payload being sent
    io:format("Payload being sent: ~s~n", [Payload]),
    
    Headers = [{"Content-Type", "application/json"}],

    %% Make HTTP POST request
    case http_request(post, URL, Headers, Payload) of
        {ok, Body} ->
            JsonMap = jsx:decode(Body, [return_maps]),
            case maps:get(<<"message">>, JsonMap, undefined) of
                undefined ->
                    io:format("Failed to update profile picture: ~s~n", [binary_to_list(Body)]),
                    {error, "Failed to update profile picture."};
                Message ->
                    io:format("Profile picture updated successfully: ~s~n", [Message]),
                    {ok, Message}
            end;
        {error, Reason} ->
            io:format("Failed to update profile picture: ~p~n", [Reason]),
            {error, Reason}
    end.

get_profile_picture(User) when is_list(User) ->
    get_profile_picture(list_to_binary(User));
get_profile_picture(User) when is_binary(User) ->
    case get_current_user() of
        {ok, Username} ->
            case get_user_token(Username) of
                {ok, Token} ->
                    QParams = <<"token=", Token/binary, "&username=", User/binary>>,
                    URL = <<"http://localhost:5000/get_profile_picture?", QParams/binary>>,
                    Headers = [{"Accept", "application/json"}],
                    case http_request(get, binary_to_list(URL), Headers, "") of
                        {ok, Body} ->
                            io:format("get_profile_picture response: ~s~n", [binary_to_list(Body)]),
                            JsonMap = jsx:decode(Body, [return_maps]),
                            case maps:get(<<"image_url">>, JsonMap, undefined) of
                                undefined ->
                                    io:format("Failed to retrieve profile picture: ~s~n", [binary_to_list(Body)]),
                                    {error, "Failed to retrieve profile picture."};
                                ImageURL ->
                                    io:format("Profile picture URL retrieved for ~s: ~s~n", [binary_to_list(User), ImageURL]),
                                    {ok, ImageURL}
                            end;
                        {error, Reason} ->
                            io:format("Failed to retrieve profile picture: ~s~n", [Reason]),
                            {error, Reason}
                    end;
                {error, Reason} ->
                    io:format("Cannot retrieve profile picture: ~s~n", [Reason]),
                    {error, Reason}
            end;
        {error, Reason} ->
            io:format("Cannot retrieve profile picture: ~s~n", [Reason]),
            {error, Reason}
    end.