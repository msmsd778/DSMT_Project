-module(message_handler).
-export([send_message/3, retrieve_messages/1]).

% Ensure inets is started
ensure_inets_started() ->
    Apps = application:which_applications(),
    case lists:keyfind(inets, 1, Apps) of
        {inets, _, _} -> ok;
        false -> application:start(inets)
    end.

% Send a message
send_message(Sender, Receiver, Message) ->
    ensure_inets_started(),
    URL = "http://localhost:5000/send_message",
    Data = io_lib:format("{\"sender\": \"~s\", \"receiver\": \"~s\", \"message\": \"~s\"}", [Sender, Receiver, Message]),
    case httpc:request(post, {URL, [], "application/json", Data}, [], []) of
        {ok, {{_, 201, _}, _, _Body}} ->  % 201 Created
            io:format("Success: Message sent successfully.~n"),
            <<"Message sent successfully.">>;
        {ok, {{_, 400, _}, _, Body}} ->  % 400 Bad Request
            io:format("Error: Bad Request - ~s~n", [Body]),
            <<"Error: Bad request.">>;
        {ok, {{_, 500, _}, _, _Body}} ->  % 500 Internal Server Error
            io:format("Error: Server error occurred.~n"),
            <<"Error: Server error occurred.">>;
        {error, Reason} ->  % Other Errors
            io:format("Error: ~p~n", [Reason]),
            {error, Reason}
    end.

% Retrieve messages
retrieve_messages(Username) ->
    ensure_inets_started(),
    URL = "http://localhost:5000/get_messages?user=" ++ Username,
    Headers = [{"Accept", "application/json"}],
    io:format("DEBUG: Sending GET request to URL: ~s with headers: ~p~n", [URL, Headers]),
    case httpc:request(get, {URL, Headers}, [], []) of
        {ok, {{_, 200, _}, _, Body}} ->  % 200 OK
            io:format("DEBUG: Response Body - ~s~n", [Body]),
            "Messages retrieved successfully.";  % Return a simple success message
        {ok, {{_, 400, _}, _, Body}} ->  % 400 Bad Request
            io:format("DEBUG: Bad Request Response - ~s~n", [Body]),
            <<"Error: Bad request.">>;
        {ok, {{_, 500, _}, _, Body}} ->  % 500 Internal Server Error
            io:format("DEBUG: Internal Server Error Response - ~s~n", [Body]),
            <<"Error: Server error occurred.">>;
        {error, Reason} ->  % Other Errors
            io:format("DEBUG: Request Error - ~p~n", [Reason]),
            {error, Reason}
    end.
