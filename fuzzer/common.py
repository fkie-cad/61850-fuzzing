from argparse import ArgumentParser

from boofuzz import Session, Target, ProcessMonitor, connections
from boofuzz.exception import BoofuzzRpcError


def setup_argparse(protocol):
    parser = ArgumentParser(description='Fuzz "{}" with boofuzz'.format(protocol))
    parser.add_argument('--debug', '-d', action='store_true', help='attach debugger to process')
    parser.add_argument('--command', default='', type=str, help='command that debugger shall start')
    parser.add_argument('--udp', action='store_true', help='use udp instead of tcp as layer 4 protocol')
    parser.add_argument('--dport', '-dp', default=26002, type=int)
    parser.add_argument('--host', type=str, help='target host for fuzzing')
    parser.add_argument('--port', type=int, help='target port for fuzzing')

    return parser.parse_args()


def setup_session(protocol):
    arguments = setup_argparse(protocol)

    if arguments.debug:
        procmon = ProcessMonitor('127.0.0.1', arguments.dport)
        procmon.set_options(start_commands=[arguments.command.split(), ])
        if not arguments.command:
            raise ValueError('Please specify command if debugger should be attached')
        try:
            if arguments.host and arguments.port:
                session = Session(
                    target=Target(
                        connection=connections.UDPSocketConnection(arguments.host, arguments.port) if arguments.udp
                        else connections.TCPSocketConnection(arguments.host, arguments.port),
                        monitors=[procmon]
                    ),
                )
            else:
                session = Session(
                    target=Target(
                        connection=connections.RawL2SocketConnection(interface='lo', ethernet_proto=33024),
                        monitors=[procmon]
                    ),
                )
        except BoofuzzRpcError:
            raise ValueError('Please start process monitor first if debugger shall be attached')
    else:
        if arguments.host and arguments.port:
            session = Session(
                target=Target(
                    connection=connections.UDPSocketConnection(arguments.host, arguments.port) if arguments.udp
                    else connections.TCPSocketConnection(arguments.host, arguments.port))
            )
        else:
            session = Session(
                target=Target(
                    connection=connections.RawL2SocketConnection(interface='lo', ethernet_proto=33024))
             )

    return session
