#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#   Copyright 2016 Futur Solo
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

from .utils import Text, Identifier
from typing import Any, Iterator, List, Sequence, Mapping, Tuple, Hashable

__all__ = ["MagicDictFrozenError", "MagicDict", "TolerantMagicDict"]

_DEFAULT_MARK = Identifier()

import inspect
import threading
import collections
import collections.abc


class MagicDictFrozenError(Exception):
    def __init__(self, *args):
        if len(args) == 0:
            super().__init__(
                "This magic dict has been frozen. "
                "You cannot modify it any more. "
                "Try to create a copy before modifying it.")

        else:
            super().__init__(*args)


class _MagicItemsView(collections.abc.ItemsView):
    def __len__(self) -> int:
        return len(self._mapping)

    def __iter__(self) -> Iterator[Tuple[Hashable, Any]]:
        with self._mapping._mutex_lock:
            pairs = self._mapping._key_value_pairs.values()

        for key, value in pairs:
            yield key, value

    def __contains__(self, pair: Tuple[Hashable, Any]) -> bool:
        with self._mapping._mutex_lock:
            return pair in self._mapping_key_value_pairs.values()

    def __le__(self, obj: collections.abc.Iterable) -> bool:
        return set(self) <= set(obj)

    def __lt__(self, obj: collections.abc.Iterable) -> bool:
        return set(self) < set(obj)

    def __eq__(self, obj: collections.abc.Iterable) -> bool:
        return list(self) == list(obj)

    def __ne__(self, obj: collections.abc.Iterable) -> bool:
        return not self.__eq__(obj)

    def __gt__(self, obj: collections.abc.Iterable) -> bool:
        return set(self) > set(obj)

    def __ge__(self, obj: collections.abc.Iterable) -> bool:
        return set(self) >= set(obj)

    def __and__(self, obj: collections.abc.Iterable) -> Sequence[Any]:
        return set(self) & set(obj)

    def __or__(self, obj: collections.abc.Iterable) -> Sequence[Any]:
        return set(self) | set(obj)

    def __sub__(self, obj: collections.abc.Iterable) -> Sequence[Any]:
        return set(self) - set(obj)

    def __xor__(self, obj: collections.abc.Iterable) -> Sequence[Any]:
        return set(self) ^ set(obj)

    def __reversed__(self) -> "_MagicItemsView":
        return reversed(self._mapping).items()


class _MagicKeysView(collections.abc.KeysView):
    def __len__(self) -> int:
        return len(self._mapping)

    def __iter__(self) -> Iterator[Hashable]:
        with self._mapping._mutex_lock:
            pairs = self._mapping._key_value_pairs.values()

        for key, _ in pairs:
            yield key

    def __contains__(self, key: Hashable) -> bool:
        with self._mapping._mutex_lock:
            return key in self._mapping._pair_identifiers.keys()

    def __le__(self, obj: collections.abc.Iterable) -> bool:
        return set(self) <= set(obj)

    def __lt__(self, obj: collections.abc.Iterable) -> bool:
        return set(self) < set(obj)

    def __eq__(self, obj: collections.abc.Iterable) -> bool:
        return list(self) == list(obj)

    def __ne__(self, obj: collections.abc.Iterable) -> bool:
        return not self.__eq__(obj)

    def __gt__(self, obj: collections.abc.Iterable) -> bool:
        return set(self) > set(obj)

    def __ge__(self, obj: collections.abc.Iterable) -> bool:
        return set(self) >= set(obj)

    def __and__(self, obj: collections.abc.Iterable) -> Sequence[Any]:
        return set(self) & set(obj)

    def __or__(self, obj: collections.abc.Iterable) -> Sequence[Any]:
        return set(self) | set(obj)

    def __sub__(self, obj: collections.abc.Iterable) -> Sequence[Any]:
        return set(self) - set(obj)

    def __xor__(self, obj: collections.abc.Iterable) -> Sequence[Any]:
        return set(self) ^ set(obj)

    def __reversed__(self) -> "_MagicKeysView":
        return reversed(self._mapping).keys()


class _MagicValuesView(collections.abc.ValuesView):
    def __len__(self) -> int:
        return len(self._mapping)

    def __iter__(self) -> Iterator[Any]:
        with self._mapping._mutex_lock:
            pairs = self._mapping._key_value_pairs.values()

        for _, value in pairs:
            yield value

    def __contains__(self, value: Any) -> bool:
        with self._mapping._mutex_lock:
            pairs = self._mapping._key_value_pairs.values()

        for _, _value in pairs:
            if _value == value:
                return True

        else:
            return False

    def __reversed__(self) -> "_MagicValuesView":
        return reversed(self._mapping).values()

    def __eq__(self, obj: collections.abc.Iterable) -> bool:
        return list(self) == list(obj)

    def __ne__(self, obj: collections.abc.Iterable) -> bool:
        return not self.__eq__(obj)


class MagicDict(collections.abc.MutableMapping):
    """
    An ordered, freezable, one-to-many mapping.
    """
    def __init__(self, *args, **kwargs):
        self._pair_identifiers = {}
        self._key_value_pairs = collections.OrderedDict()
        self._frozen = False

        self._mutex_lock = threading.Lock()

        if len(args) > 0 or len(kwargs) > 0:
            self.update(*args, **kwargs)

    def __getitem__(self, key: Hashable) -> Any:
        with self._mutex_lock:
            identifier = self._pair_identifiers[key][0]
            _, value = self._key_value_pairs[identifier]
            return value

    def __setitem__(self, key: Hashable, value: Any):
        if self._frozen:
            raise MagicDictFrozenError

        if key in self.keys():
            del self[key]

        identifier = Identifier()

        with self._mutex_lock:
            self._pair_identifiers[key] = [identifier]
            self._key_value_pairs[identifier] = (key, value)

    def __delitem__(self, key: Hashable):
        if self._frozen:
            raise MagicDictFrozenError

        with self._mutex_lock:
            identifiers = self._pair_identifiers.pop(key)
            for identifier in identifiers:
                del self._key_value_pairs[identifier]

    def __iter__(self) -> Iterator[Any]:
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self._key_value_pairs)

    def __contains__(self, key: Hashable) -> bool:
        return key in self._pair_identifiers

    def __eq__(self, obj: Mapping[Any, Any]) -> bool:
        if not isinstance(obj, collections.abc.Mapping):
            return False

        return self.items() == obj.items()

    def __ne__(self, obj: Mapping[Any, Any]) -> bool:
        return not self.__eq__(obj)

    def __str__(self) -> Text:
        content_list = [(key, value) for (key, value) in self.items()]

        return "MagicDict({})".format(repr(content_list))

    def __reversed__(self) -> "MagicDict":
        magic_dict = MagicDict()
        reversed_values = []
        with self._mutex_lock:
            reversed_values.extend(reversed(self._key_value_pairs.values()))

        for key, value in reversed_values:
            magic_dict.add(key, value)

        return magic_dict

    def add(self, key: Hashable, value: Any):
        if self._frozen:
            raise MagicDictFrozenError

        if key in self:
            identifier = Identifier()

            with self._mutex_lock:
                self._pair_identifiers[key].append(identifier)
                self._key_value_pairs[identifier] = (key, value)

        else:
            self[key] = value

    def pop(self, key: Hashable) -> Any:
        if self._frozen:
            raise MagicDictFrozenError

        with self._mutex_lock:
            identifier = self._pair_identifiers[key].pop()

            if len(self._pair_identifiers[key]) == 0:
                del self._pair_identifiers[key]

            _, value = self._key_value_pairs.pop(identifier)

        return value

    def popitem(self) -> (Hashable, Any):
        if self._frozen:
            raise MagicDictFrozenError

        with self._mutex_lock:
            identifier, pair = self._key_value_pairs.popitem()
            self._pair_identifiers[key].pop()

            if len(self._pair_identifiers[key]) == 0:
                del self._pair_identifiers[key]

        return pair

    def clear(self):
        if self._frozen:
            raise MagicDictFrozenError

        with self._mutex_lock:
            self._key_value_pairs.clear()
            self._pair_identifiers.clear()

    def update(self, *args, **kwargs):
        if self._frozen:
            raise MagicDictFrozenError

        if len(args) == 0:
            for key, value in kwargs.items():
                self.add(key, value)

        elif len(args) == 1:
            if hasattr(args[0], "items"):  # Dict Like Object.
                for key, value in args[0].items():
                    self.add(key, value)

            else:
                for key, value in args[0]:  # Key, Value Pair Iterator.
                    self.add(key, value)

        else:
            raise TypeError(
                "update expected at most 1 positional argument, got {}."
                .format(len(args)))

    def setdefault(self, key: Hashable, default: Any=None) -> Any:
        if self._frozen:
            raise MagicDictFrozenError

        if key in self.keys():
            return self[key]

        self[key] = default
        return default

    @staticmethod
    def fromkeys(seq: Sequence[Any], value: Any=None) -> "MagicDict":
        magic_dict = MagicDict()
        for key in seq:
            magic_dict[key] = value

        return magic_dict

    def get_first(self, key: Hashable, default: Any=None) -> Any:
        with self._mutex_lock:
            identifier = self._pair_identifiers.get(key, [_DEFAULT_MARK])[0]
            if identifier is _DEFAULT_MARK:
                return default

            _, value = self._key_value_pairs[identifier]
            return value

    def get_last(self, key: Hashable, default: Any=None) -> Any:
        with self._mutex_lock:
            identifier = self._pair_identifiers.get(key, [_DEFAULT_MARK])[-1]
            if identifier is _DEFAULT_MARK:
                return default

            _, value = self._key_value_pairs[identifier]
            return value

    def get_iter(self, key: Hashable) -> Iterator[Any]:
        with self._mutex_lock:
            identifiers = self._pair_identifiers.get(key, [])

        for identifier in identifiers:
            with self._mutex_lock:
                _, value = self._key_value_pairs[identifier]

            yield value

    def get_list(self, key: Hashable) -> List[Any]:
        return list(self.get_iter(key))

    def items(self) -> _MagicItemsView:
        return _MagicItemsView(self)

    def keys(self) -> _MagicKeysView:
        return _MagicKeysView(self)

    def values(self) -> _MagicValuesView:
        return _MagicValuesView(self)

    def freeze(self):
        self._frozen = True

    def is_frozen(self) -> bool:
        return self._frozen

    def copy(self) -> "MagicDict":
        return MagicDict(self)

    __copy__ = copy
    __repr__ = __str__
    get = get_first


class TolerantMagicDict(MagicDict):
    """
    An ordered, freezable, case-insensitive, one-to-many mapping.

    Everything in this implementation is the same as `MagicDict`,
    but Keys must be str and are case-insensitive.

    **This doesn't mean that the normal `MagicDict` is mean.**
    """

    def __setitem__(self, key: Text, value: Any):
        if not isinstance(key, str):
            raise TypeError(
                "Keys of a `TolerantMagicDict` should be str.")

        return super().__setitem__(key.lower(), value)

    def __str__(self):
        content_list = [(key, value) for (key, value) in self.items()]

        return "TolerantMagicDict({})".format(str(content_list))

    def __getitem__(self, key: Text) -> Any:
        return super().__getitem__(key.lower())

    def __delitem__(self, key: Text):
        super().__delitem__(key.lower())

    def __contains__(self, key: Text) -> bool:
        return key.lower() in self._pair_identifiers

    def __reversed__(self) -> "MagicDict":
        tolerant_magic_dict = TolerantMagicDict()
        reversed_values = []
        with self._mutex_lock:
            reversed_values.extend(reversed(self._key_value_pairs.values()))

        for key, value in reversed_values:
            tolerant_magic_dict.add(key, value)

        return tolerant_magic_dict

    def add(self, key: Text, value: Any):
        if not isinstance(key, str):
            raise TypeError(
                "Keys of a `TolerantMagicDict` should be str.")

        return super().add(key.lower(), value)

    def pop(self, key: Text) -> Any:
        return super().pop(key.lower())

    def setdefault(self, key: Text, default: Any=None) -> Any:
        return super().setdefault(key.lower(), default=default)

    @staticmethod
    def fromkeys(seq: Sequence[Text], value: Any=None) -> "MagicDict":
        tolerant_magic_dict = TolerantMagicDict()
        for key in seq:
            tolerant_magic_dict[key] = value

        return tolerant_magic_dict

    def get_first(self, key: Text, default: Any=None) -> Any:
        return super().get_first(key.lower(), default=default)

    def get_last(self, key: Hashable, default: Any=None) -> Any:
        return super().get_last(key.lower(), default=default)

    def get_iter(self, key: Text) -> Iterator[Any]:
        return super().get_iter(key.lower())

    def copy(self):
        return TolerantMagicDict(self)

    __copy__ = copy
    __repr__ = __str__
    get = get_first

