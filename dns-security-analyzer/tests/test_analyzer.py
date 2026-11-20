import pytest
from app.analyzer import normalize_domain, analyze_spf, analyze_dmarc

@pytest.mark.parametrize(('value','expected'), [
    ('https://Example.COM:443/path?q=1','example.com'),
    ('example.com.','example.com'),
    ('bücher.de','xn--bcher-kva.de'),
])
def test_normalize_domain(value, expected):
    assert normalize_domain(value) == expected

@pytest.mark.parametrize('value', ['', 'localhost', '-bad.example', 'bad..example', 'example.com:bad'])
def test_invalid_domain(value):
    with pytest.raises(ValueError):
        normalize_domain(value)

def test_spf_hard_fail():
    result=analyze_spf(['"v=spf1 include:_spf.example.net -all"'])
    assert result['grade']=='good'
    assert result['status']=='hard_fail'

def test_spf_multiple():
    assert analyze_spf(['v=spf1 -all','v=spf1 ~all'])['status']=='multiple'

def test_dmarc_reject():
    result=analyze_dmarc(['"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'])
    assert result['policy']=='reject'
    assert result['grade']=='good'
