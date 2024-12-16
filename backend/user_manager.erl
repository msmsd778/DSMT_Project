-module(user_manager).
-export([register_user/2, login_user/2]).

ensure_inets_started() ->
    Apps = application:which_applications(),
    case lists:keyfind(inets, 1, Apps) of
        {inets, _, _} -> ok;  % inets is already started
        false -> application:start(inets)  % Start inets if not running
    end.

register_user(Username, Password) ->
    ensure_inets_started(),  % Ensure inets is started
    URL = "http://localhost:5000/register",
    Data = io_lib:format("{\"username\": \"~s\", \"password\": \"~s\"}", [Username, Password]),
    case httpc:request(post, {URL, [], "application/json", Data}, [], []) of
        {ok, {{_, 201, _}, _, _Body}} ->  % 201 Created
            io:format("Success: User registered successfully.~n"),
            <<"User registered successfully.">>;
        {ok, {{_, 400, _}, _, Body}} ->  % 400 Bad Request
            io:format("Raw response body: ~s~n", [Body]),  % Log the raw body
            case is_duplicate_user(Body) of
                true ->
                    io:format("Error: Registration failed - Duplicate username.~n"),
                    <<"Error: Duplicate username.">>;
                false ->
                    io:format("Error: Registration failed - Bad request.~n"),
                    <<"Error: Bad request.">>
            end;
        {ok, {{_, 500, _}, _, _Body}} ->  % 500 Internal Server Error
            io:format("Error: Server error occurred.~n"),
            <<"Error: Server error occurred.">>;
        {error, Reason} ->  % Other Errors
            io:format("Error: ~p~n", [Reason]),
            {error, Reason}
    end.

is_duplicate_user(Body) ->
    lists:member("Username already exists.", string:tokens(Body, " ")).

login_user(Username, Password) ->
    ensure_inets_started(),  % Ensure inets is started
    URL = "http://localhost:5000/login",
    Data = io_lib:format("{\"username\": \"~s\", \"password\": \"~s\"}", [Username, Password]),
    case httpc:request(post, {URL, [], "application/json", Data}, [], []) of
        {ok, {{_, 200, _}, _, _Body}} ->  % 200 OK
            io:format("Success: Login successful.~n"),
            <<"Login successful.">>;
        {ok, {{_, 401, _}, _, _Body}} ->  % 401 Unauthorized
            io:format("Error: Invalid credentials.~n"),
            <<"Error: Invalid credentials.">>;
        {error, Reason} ->  % Other Errors
            io:format("Error: ~p~n", [Reason]),
            {error, Reason}
    end.
