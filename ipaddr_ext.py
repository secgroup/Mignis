# -*- coding: utf-8 -*-
'''
IPv4 Range support for ipaddress module.

Provides IPv4Range class to represent IP address ranges (e.g., 10.0.1.1-10.0.1.100).
'''

from ipaddress import IPv4Address, IPv4Network, AddressValueError
from typing import Union, Iterator


class IPv4Range:
    """Represents a range of IPv4 addresses.

    Attributes:
        ip_from: First IP address in the range (IPv4Address)
        ip_to: Last IP address in the range (IPv4Address)
        _ip_from: Integer representation of first IP
        _ip_to: Integer representation of last IP
        _version: IP version (always 4 for IPv4)

    Example:
        >>> r = IPv4Range('10.0.1.1-10.0.1.100')
        >>> IPv4Address('10.0.1.50') in r
        True
        >>> str(r)
        '10.0.1.1-10.0.1.100'
    """

    _version = 4

    def __init__(self, address: str):
        """Initialize an IPv4 range.

        Args:
            address: String in format 'ip1-ip2' (e.g., '10.0.1.1-10.0.1.100')

        Raises:
            AddressValueError: If address format is invalid
        """
        self._cache = {}

        # Parse the range string
        addr_parts = str(address).split('-')
        if len(addr_parts) != 2:
            raise AddressValueError(f"Invalid range format: {address}")

        try:
            self.ip_from = IPv4Address(addr_parts[0].strip())
            self.ip_to = IPv4Address(addr_parts[1].strip())
        except Exception as e:
            raise AddressValueError(f"Invalid IP address in range: {address}") from e

        self._ip_from = int(self.ip_from)
        self._ip_to = int(self.ip_to)

        if self._ip_from > self._ip_to:
            raise AddressValueError(f"Range start {self.ip_from} is greater than end {self.ip_to}")

    def __str__(self) -> str:
        """Return string representation in format 'ip1-ip2'."""
        return f'{self.ip_from}-{self.ip_to}'

    def __repr__(self) -> str:
        """Return detailed string representation."""
        return f'{self.__class__.__name__}({str(self)!r})'

    def __hash__(self) -> int:
        """Return hash for use in sets and dicts."""
        return hash((self._ip_from, self._ip_to))

    def __eq__(self, other) -> bool:
        """Check equality with another IPv4Range."""
        if not isinstance(other, IPv4Range):
            return NotImplemented
        return self._ip_from == other._ip_from and self._ip_to == other._ip_to

    def __ne__(self, other) -> bool:
        """Check inequality with another IPv4Range."""
        eq = self.__eq__(other)
        return NotImplemented if eq is NotImplemented else not eq

    def __lt__(self, other) -> bool:
        """Compare if this range is less than another."""
        if not isinstance(other, (IPv4Range, IPv4Network)):
            return NotImplemented
        if isinstance(other, IPv4Range):
            return (self._ip_from, self._ip_to) < (other._ip_from, other._ip_to)
        # Comparing with IPv4Network
        return self._ip_from < int(other.network_address)

    def __le__(self, other) -> bool:
        """Compare if this range is less than or equal to another."""
        return self < other or self == other

    def __gt__(self, other) -> bool:
        """Compare if this range is greater than another."""
        if not isinstance(other, (IPv4Range, IPv4Network)):
            return NotImplemented
        if isinstance(other, IPv4Range):
            return (self._ip_from, self._ip_to) > (other._ip_from, other._ip_to)
        return self._ip_from > int(other.network_address)

    def __ge__(self, other) -> bool:
        """Compare if this range is greater than or equal to another."""
        return self > other or self == other

    def __contains__(self, other: Union[IPv4Address, IPv4Network, 'IPv4Range']) -> bool:
        """Check if an IP address, network, or range is within this range.

        Args:
            other: IPv4Address, IPv4Network, or IPv4Range to check

        Returns:
            True if other is contained in this range
        """
        if isinstance(other, IPv4Address):
            return self._ip_from <= int(other) <= self._ip_to
        elif isinstance(other, IPv4Network):
            return (self._ip_from <= int(other.network_address) and
                    self._ip_to >= int(other.broadcast_address))
        elif isinstance(other, IPv4Range):
            return (self._ip_from <= other._ip_from and
                    self._ip_to >= other._ip_to)
        return False

    def __iter__(self) -> Iterator[IPv4Address]:
        """Iterate over all IP addresses in the range."""
        current = self._ip_from
        while current <= self._ip_to:
            yield IPv4Address(current)
            current += 1

    def __getitem__(self, index: int) -> IPv4Address:
        """Get IP address at given index.

        Args:
            index: Index in range (can be negative for reverse indexing)

        Returns:
            IPv4Address at that position

        Raises:
            IndexError: If index is out of range
        """
        if index >= 0:
            ip_int = self._ip_from + index
            if ip_int > self._ip_to:
                raise IndexError("Index out of range")
            return IPv4Address(ip_int)
        else:
            # Negative indexing
            ip_int = self._ip_to + index + 1
            if ip_int < self._ip_from:
                raise IndexError("Index out of range")
            return IPv4Address(ip_int)

    @property
    def num_addresses(self) -> int:
        """Return the number of addresses in this range."""
        return self._ip_to - self._ip_from + 1

    def overlaps(self, other: Union[IPv4Network, 'IPv4Range']) -> bool:
        """Check if this range overlaps with another range or network.

        Args:
            other: IPv4Network or IPv4Range to check

        Returns:
            True if ranges overlap
        """
        if isinstance(other, IPv4Network):
            other_start = int(other.network_address)
            other_end = int(other.broadcast_address)
        elif isinstance(other, IPv4Range):
            other_start = other._ip_from
            other_end = other._ip_to
        else:
            return False

        return not (self._ip_to < other_start or self._ip_from > other_end)
