class TrieNode:
    """A single node in the Trie. Represents one character of a key."""

    def __init__(self):
        self.children: dict[str, "TrieNode"] = {}
        self.is_end: bool = False       # True if this node completes a full key


class Trie:

    def __init__(self):
        self.root = TrieNode()

    def insert(self, key: str) -> None:
        key = key.upper()
        node = self.root
        for char in key:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end = True

    def delete(self, key: str) -> bool:
        key = key.upper()

        def _delete(node: TrieNode, key: str, depth: int) -> bool:
            if depth == len(key):
                if not node.is_end:
                    return False  # Key not in trie
                node.is_end = False
                return True

            char = key[depth]
            if char not in node.children:
                return False

            deleted = _delete(node.children[char], key, depth + 1)

            # Prune node if it has no children and is not end of another key
            if deleted and not node.children[char].children and not node.children[char].is_end:
                del node.children[char]

            return deleted

        return _delete(self.root, key, 0)

    def contains(self, key: str) -> bool:
        """
        Check if an exact key exists in the trie.
        Time: O(L).
        """
        key = key.upper()
        node = self.root
        for char in key:
            if char not in node.children:
                return False
            node = node.children[char]
        return node.is_end

    def search(self, prefix: str) -> list[str]:

        prefix = prefix.upper()
        results: list[str] = []

        node = self.root
        for char in prefix:
            if char not in node.children:
                return []  
            node = node.children[char]

        self._dfs(node, prefix, results)
        return sorted(results)

    def _dfs(self, node: TrieNode, current: str, results: list[str]) -> None:
        if node.is_end:
            results.append(current)
        for char, child in node.children.items():
            self._dfs(child, current + char, results)

    def all_keys(self) -> list[str]:
        return self.search("")
