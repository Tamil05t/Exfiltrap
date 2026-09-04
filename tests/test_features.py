"""Unit tests for M2 — feature extraction."""

from exfiltrap.features import (
    FeatureExtractor,
    base_domain,
    extract_static,
    leftmost_label,
    shannon_entropy,
)


class TestShannonEntropy:
    def test_empty_string_is_zero(self):
        assert shannon_entropy("") == 0.0

    def test_single_repeated_char_is_zero(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_uniform_16_symbol_alphabet_is_4_bits(self):
        # Each of the 16 hex characters appears exactly once -> log2(16) = 4.
        assert shannon_entropy("0123456789abcdef") == 4.0

    def test_known_mixed_value(self):
        # "aabb": p(a)=p(b)=0.5 -> H = -(0.5*log2(0.5))*2 = 1.0
        assert abs(shannon_entropy("aabb") - 1.0) < 1e-12

    def test_known_8_4_4_distribution(self):
        # 8 chars: one symbol x4, two symbols x2 -> p = 1/2, 1/4, 1/4
        import math
        expected = -(0.5 * math.log2(0.5) + 2 * (0.25 * math.log2(0.25)))
        assert abs(shannon_entropy("abcaabca") - expected) < 1e-12

    def test_case_sensitive(self):
        assert shannon_entropy("Aa") > 0.0  # two distinct symbols


class TestLabels:
    def test_leftmost_label(self):
        assert leftmost_label("mfzg6ldq.tunnel.evil.example.") == "mfzg6ldq"
        assert leftmost_label("example.com") == "example"

    def test_base_domain_trailing_dot(self):
        assert base_domain("a.b.example.com.") == "example.com"

    def test_base_domain_two_labels(self):
        assert base_domain("example.com") == "example.com"

    def test_base_domain_single_label(self):
        assert base_domain("localhost") == "localhost"

    def test_base_domain_deep(self):
        assert base_domain("x.y.z.w.example.org") == "example.org"


class TestFeatureExtractor:
    def test_basic_vector(self):
        fx = FeatureExtractor()
        vec = fx.extract("www.google.com", 100.0)
        assert vec.leftmost_label == "www"
        assert vec.base_domain == "google.com"
        assert vec.length == len("www.google.com")
        assert vec.subdomain_count == 1  # 3 labels - 2 ("www" counts as one)
        assert vec.frequency == 1.0  # first query for this base domain
        assert vec.timestamp == 100.0
        assert vec.qname == "www.google.com"

    def test_subdomain_count(self):
        fx = FeatureExtractor()
        vec = fx.extract("a.b.c.d.example.org", 0.0)
        assert vec.subdomain_count == 4  # 6 labels - 2

    def test_frequency_window_pruning(self):
        fx = FeatureExtractor(frequency_window=60.0)
        # Same base domain at t=0,10,30,59 -> running counts 1,2,3,4.
        for expected, t in enumerate((0, 10, 30, 59), start=1):
            assert fx.extract("api.example.com", float(t)).frequency == float(expected)
        # t=61 prunes the t=0 entry (61-60=1 >= 0): {10,30,59} + this = 4
        assert fx.extract("api.example.com", 61.0).frequency == 4.0
        # t=200 prunes everything older than 140: only this query remains.
        assert fx.extract("api.example.com", 200.0).frequency == 1.0

    def test_domains_tracked_independently(self):
        fx = FeatureExtractor()
        fx.extract("a.first.org", 0.0)
        fx.extract("a.first.org", 1.0)
        assert fx.extract("a.second.org", 2.0).frequency == 1.0
        assert fx.extract("a.first.org", 3.0).frequency == 3.0

    def test_high_entropy_label_measured(self):
        fx = FeatureExtractor()
        vec = fx.extract("0123456789abcdef.tunnel.evil.example", 0.0)
        assert abs(vec.entropy - 4.0) < 1e-12


class TestExtractStatic:
    def test_frequency_zero_and_stateless(self):
        vec = extract_static("x.y.example.com")
        assert vec.frequency == 0.0
        assert vec.timestamp == 0.0
        again = extract_static("x.y.example.com")
        assert again == vec  # frozen dataclass, fully deterministic

    def test_matches_stateful_extraction(self):
        fx = FeatureExtractor()
        dyn = fx.extract("abc.def.example.net", 5.0)
        stat = extract_static("abc.def.example.net")
        assert dyn.entropy == stat.entropy
        assert dyn.length == stat.length
        assert dyn.subdomain_count == stat.subdomain_count
