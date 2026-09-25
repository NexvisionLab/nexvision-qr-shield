from app.url_intelligence import confusable_skeleton, levenshtein, shannon_entropy


def test_cyrillic_confusable_skeleton():
    assert confusable_skeleton("раypal") == "paypal"


def test_levenshtein_limit():
    assert levenshtein("micros0ft", "microsoft", 2) <= 2
    assert levenshtein("unrelated", "paypal", 2) > 2


def test_entropy_basics():
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("abcdefgh") > 2
