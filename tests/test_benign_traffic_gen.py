"""Unit tests for the benign traffic generator (no network)."""

import pytest

import tools.benign_traffic_gen as gen


class TestLoadDomains:
    def test_parses_rank_domain_csv(self, tmp_path):
        csv = tmp_path / "d.csv"
        csv.write_text("1,google.com\n2,youtube.com\nnot,a,row\n3,example.org\n")
        assert gen.load_domains(csv) == ["google.com", "youtube.com", "example.org"]

    def test_fallback_when_missing(self, tmp_path):
        domains = gen.load_domains(tmp_path / "nope.csv")
        assert "google.com" in domains and len(domains) >= 20

    def test_real_corpus_present_in_repo(self):
        domains = gen.load_domains()
        assert len(domains) >= 1000  # the bundled top-50k corpus


class TestGenerateTraffic:
    def test_count_matches_qps(self):
        records = gen.generate_traffic(600.0, qps=2.0, domains=["a.com"])
        assert len(records) == 1200

    def test_minimum_one_query(self):
        assert len(gen.generate_traffic(0.001, qps=1.0)) == 1

    def test_all_benign_labels(self):
        records = gen.generate_traffic(100.0, qps=5.0)
        assert all(not r.is_malicious for r in records)
        assert all("meta" in ("",) or r.meta.get("domain") for r in records)

    def test_qnames_are_subdomains_of_pool(self):
        pool = ["example.com", "example.org"]
        records = gen.generate_traffic(50.0, qps=4.0, domains=pool, seed=7)
        for rec in records:
            assert any(rec.query.qname == d or rec.query.qname.endswith("." + d)
                       for d in pool)

    def test_timestamps_increase_and_stay_sane(self):
        records = gen.generate_traffic(100.0, qps=1.0, seed=3)
        stamps = [r.query.timestamp for r in records]
        assert stamps == sorted(stamps)
        assert stamps[-1] < 100.0 * 3  # Poisson sanity bound

    def test_deterministic_given_seed(self):
        a = gen.generate_traffic(100.0, qps=2.0, seed=11, domains=["x.com"])
        b = gen.generate_traffic(100.0, qps=2.0, seed=11, domains=["x.com"])
        assert [r.query.qname for r in a] == [r.query.qname for r in b]

    def test_label_mix_produced(self):
        records = gen.generate_traffic(5000.0, qps=1.0, seed=5)
        names = {r.query.qname for r in records}
        assert any(n.count(".") == 1 for n in names)  # bare domains occur
        assert any(n.count(".") >= 2 for n in names)  # and prefixed ones too

    def test_rejects_bad_duration(self):
        with pytest.raises(ValueError):
            gen.generate_traffic(0.0)


class TestLabSafety:
    def test_refuses_public_target(self):
        with pytest.raises(SystemExit) as exc:
            gen._validate_lab_target("1.1.1.1")
        assert exc.value.code == 2

    def test_accepts_lab_target(self):
        gen._validate_lab_target("10.99.0.1")
