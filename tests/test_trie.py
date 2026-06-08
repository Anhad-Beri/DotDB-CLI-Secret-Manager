import pytest
from vault.trie import Trie


@pytest.fixture
def trie():
    t = Trie()
    for key in ["DB_HOST", "DB_PASSWORD", "DB_URL", "AWS_SECRET", "AWS_KEY", "GITHUB_TOKEN"]:
        t.insert(key)
    return t


def test_contains_inserted_key(trie):
    assert trie.contains("DB_HOST")
    assert trie.contains("AWS_SECRET")


def test_does_not_contain_missing_key(trie):
    assert not trie.contains("STRIPE_KEY")


def test_search_prefix_returns_all_matches(trie):
    results = trie.search("DB_")
    assert set(results) == {"DB_HOST", "DB_PASSWORD", "DB_URL"}


def test_search_prefix_aws(trie):
    results = trie.search("AWS_")
    assert set(results) == {"AWS_SECRET", "AWS_KEY"}


def test_search_no_matches(trie):
    assert trie.search("NONEXISTENT_") == []


def test_search_empty_prefix_returns_all(trie):
    all_keys = trie.all_keys()
    assert len(all_keys) == 6
    assert "DB_HOST" in all_keys


def test_delete_removes_key(trie):
    trie.delete("DB_HOST")
    assert not trie.contains("DB_HOST")
    assert trie.contains("DB_PASSWORD")


def test_delete_returns_false_for_missing_key(trie):
    assert not trie.delete("NONEXISTENT_KEY")


def test_case_insensitive_insert_and_search(trie):
    trie.insert("stripe_key")
    assert trie.contains("STRIPE_KEY")
    assert "STRIPE_KEY" in trie.search("STRIPE")