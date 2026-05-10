"""Test POST form enhancement - hidden fields preserved"""
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.path.insert(0, "C:/Users/HZR/.qclaw/workspace-agent-b7ed571b/wvs-v18")

from wvs.modules.forms.form_enhancer import FormEnhancer, FormField, EnhancedForm

def test_hidden_field_extraction():
    """Test: hidden fields extracted with default values"""
    html = '''
    <form action="/submit" method="POST">
        <input type="hidden" name="csrf_token" value="abc123">
        <input type="hidden" name="page" value="dns-lookup.php">
        <input type="text" name="target_host" value="">
        <input type="submit" name="submit" value="Lookup">
    </form>
    '''
    enhancer = FormEnhancer()
    forms = enhancer.extract_forms(html, "http://test.com/form")
    
    assert len(forms) == 1, f"Expected 1 form, got {len(forms)}"
    form = forms[0]
    
    # Check hidden fields preserved
    assert "csrf_token" in form.fields, "csrf_token missing"
    assert form.fields["csrf_token"].type == "hidden", "csrf_token not hidden"
    assert form.fields["csrf_token"].default_value == "abc123", "csrf_token value wrong"
    
    assert "page" in form.fields, "page field missing"
    assert form.fields["page"].default_value == "dns-lookup.php", "page value wrong"
    
    # Check testable fields (hidden fields ARE testable for injection)
    testable = form.get_testable_fields()
    assert "target_host" in testable, "target_host not testable"
    assert "csrf_token" in testable, "csrf_token should be testable (hidden fields can have injection)"
    assert "page" in testable, "page should be testable (hidden fields can have LFI)"
    
    print("✅ test_hidden_field_extraction PASS")
    return True

def test_get_post_data_preserves_hidden():
    """Test: get_post_data() preserves hidden field values"""
    form = EnhancedForm(
        url="http://test.com/submit",
        method="POST",
        fields={
            "csrf_token": FormField(name="csrf_token", type="hidden", value="abc123", default_value="abc123", is_testable=False),
            "page": FormField(name="page", type="hidden", value="dns-lookup.php", default_value="dns-lookup.php", is_testable=False),
            "target_host": FormField(name="target_host", type="text", value="", default_value="", is_testable=True),
            "submit": FormField(name="submit", type="submit", value="Lookup", default_value="Lookup", is_testable=False),
        }
    )
    
    # Normal POST data (no test field)
    data = form.get_post_data()
    assert data["csrf_token"] == "abc123", "csrf_token not preserved"
    assert data["page"] == "dns-lookup.php", "page not preserved"
    assert data["target_host"] == "", "target_host missing"
    assert "submit" not in data, "submit should not be in POST data"
    
    # Test with payload injection
    data_with_payload = form.get_post_data(test_field="target_host", test_value="; id")
    assert data_with_payload["csrf_token"] == "abc123", "csrf_token lost during test"
    assert data_with_payload["page"] == "dns-lookup.php", "page lost during test"
    assert data_with_payload["target_host"] == "; id", "payload not injected"
    
    print("✅ test_get_post_data_preserves_hidden PASS")
    return True

def test_mutillidae_dns_lookup_form():
    """Test: Mutillidae DNS lookup form (real-world case)"""
    html = '''
    <form action="/mutillidae/index.php" method="POST">
        <input type="hidden" name="page" value="dns-lookup.php">
        <input type="hidden" name="title" value="DNS Lookup">
        <input type="text" name="target_host" id="target_host">
        <input type="submit" value="Lookup DNS">
    </form>
    '''
    enhancer = FormEnhancer()
    forms = enhancer.extract_forms(html, "http://192.168.18.131/mutillidae/")
    
    assert len(forms) == 1
    form = forms[0]
    
    # Generate POST data with CMDi payload
    post_data = form.get_post_data(test_field="target_host", test_value="; whoami")
    
    # Verify all fields present
    assert post_data["page"] == "dns-lookup.php", f"page wrong: {post_data.get('page')}"
    assert post_data["title"] == "DNS Lookup", f"title wrong: {post_data.get('title')}"
    assert post_data["target_host"] == "; whoami", f"payload wrong: {post_data.get('target_host')}"
    
    print("✅ test_mutillidae_dns_lookup_form PASS")
    print(f"   POST data: {post_data}")
    return True

def test_select_and_textarea():
    """Test: select options and textarea default values"""
    html = '''
    <form action="/submit" method="POST">
        <input type="hidden" name="id" value="123">
        <select name="category">
            <option value="news">News</option>
            <option value="tech" selected>Tech</option>
            <option value="life">Life</option>
        </select>
        <textarea name="comment">Default comment</textarea>
        <input type="submit">
    </form>
    '''
    enhancer = FormEnhancer()
    forms = enhancer.extract_forms(html, "http://test.com/")
    
    form = forms[0]
    assert form.fields["category"].type == "select"
    assert form.fields["category"].default_value == "tech", "Selected option not captured"
    assert "news" in form.fields["category"].options and "life" in form.fields["category"].options
    
    assert form.fields["comment"].type == "textarea"
    assert form.fields["comment"].default_value == "Default comment"
    
    print("✅ test_select_and_textarea PASS")
    return True

if __name__ == "__main__":
    print("=" * 60)
    print("POST Form Enhancement Tests")
    print("=" * 60)
    
    all_pass = True
    all_pass &= test_hidden_field_extraction()
    all_pass &= test_get_post_data_preserves_hidden()
    all_pass &= test_mutillidae_dns_lookup_form()
    all_pass &= test_select_and_textarea()
    
    print("=" * 60)
    print(f"Result: {'ALL PASS ✅' if all_pass else 'FAILED ❌'}")
