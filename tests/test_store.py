from triagetool import store


def test_record_round_trip():
    assert store.load("acme/app", "GHSA-2222-3333-4444") == {}
    store.save("acme/app", "GHSA-2222-3333-4444", {"claim": {"summary": "s"}})
    record = store.load("acme/app", "GHSA-2222-3333-4444")
    assert record["claim"] == {"summary": "s"}
    assert record["saved_at"]
    assert store.load("acme/other", "GHSA-2222-3333-4444") == {}


def test_repos_are_the_ones_fetched():
    store.save("acme/app", "advisories", {"advisories": []})
    store.save("acme/lib", "threatmodel", {"error": "boom"})
    assert store.repos() == ["acme/app"]
