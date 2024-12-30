%% user_node.erl
%% This module starts a new Erlang node that represents a browser node
%% and then registers it with the node_manager.

-module(user_node).
-export([start/0, register_node_with_manager/1]).

%% Usage:
%%   1) Start node_manager:
%%        erl -sname node_manager
%%        1> c(node_manager).
%%        2> node_manager:init().
%%   2) Start this user node:
%%        erl -sname edge_node
%%        1> c(user_node).
%%        2> user_node:start().
%%   The user_node:start() will attempt to connect to 'node_manager@Asus-k571gt'
%%   and call handle_register_node in the manager.

start() ->
    %% Adjust the manager node name as needed:
    NodeManagerAtom = 'node_manager@Asus-k571gt',

    %% Check if we can connect to the manager:
    case net_adm:ping(NodeManagerAtom) of
        pong ->
            io:format("~n[UserNode] Connected to Manager: ~p~n",[NodeManagerAtom]),
            %% Convert our own node name (this node) to binary:
            NodeNameBin = list_to_binary(atom_to_list(node())),
            %% Actually register with manager:
            register_node_with_manager({NodeManagerAtom, NodeNameBin});
        pang ->
            io:format("[UserNode] Failed to connect to ~p. Is node_manager running?~n", [NodeManagerAtom]),
            error
    end.

%% Actually registers the node with the manager via an RPC call.
%% IMPORTANT:
%%  handle_register_node in node_manager.erl expects a single argument (a binary).
%%  So we must pass [NodeNameBin] as the final argument list, not [[NodeNameBin]].
register_node_with_manager({NodeManagerAtom, NodeNameBin}) ->
    %% The 4th argument to rpc:call/4 is a list of function arguments.
    %% handle_register_node/1 has arity 1 => we pass [NodeNameBin].
    Resp = rpc:call(NodeManagerAtom, node_manager, handle_register_node, [NodeNameBin]),
    io:format("[UserNode] Registration response: ~p~n",[Resp]),
    ok.
