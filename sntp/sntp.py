"""SNTP server module"""
from typing import Tuple, override
import asyncio
import struct
import json
import time


class SNTPProtocol(asyncio.DatagramProtocol):
    """SNTP Protocol implementation"""

    def __init__(self, shift: int = 0) -> None:
        super().__init__()
        self.transport: asyncio.DatagramTransport = None
        self.packet_format = struct.Struct('!BBBBIIIQQQQ')
        self.ntp_offset = 2208988800
        self.shift = shift

    @override
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    @override
    def datagram_received(self, data: bytes, addr: tuple) -> None:
        print(f'Received SNTP packet from {addr}')
        response = self.create_packet(data)
        self.transport.sendto(response, addr)

    def create_packet(self, data: bytes) -> bytes:
        """Creates SNTP packet

        Args:
            data (bytes): Received packet

        Returns:
            bytes: Response packet
        """
        received_packet = self.packet_format.unpack(data)
        response_packet = self.packet_format.pack(
            0b00100100, 1, 0, 0, 0, 0, 0, 0,
            received_packet[10], self.calculate_time(),
            self.calculate_time()
        )
        return response_packet

    def calculate_time(self) -> int:
        """Calculates current time

        Returns:
            int: Current time
        """
        return int(time.time() + self.ntp_offset + self.shift) * 2**32


async def main():
    # get configs
    with open('config.json', mode='rb') as file:
        data = json.load(file)
        address: Tuple[str, int] = data['host'], data['port']
        shift: int = data['shift']

    # get running eventloop
    loop = asyncio.get_event_loop()

    # make connection
    transport, _ = await loop.create_datagram_endpoint(
        lambda: SNTPProtocol(shift), local_addr=address)

    try:
        await asyncio.sleep(3600)  # serve for 1 hour
    except asyncio.CancelledError:
        print('Server was shut down')  # in case if task was cancelled
    finally:
        transport.close()  # close transport

if __name__ == '__main__':
    asyncio.run(main())
