// Show/Hide password toggles
document.querySelectorAll('[data-toggle-password]').forEach(function(toggle){
  toggle.addEventListener('change', function(){
    const targetId = toggle.getAttribute('data-toggle-password');
    const input = document.getElementById(targetId);
    if (input) input.type = toggle.checked ? 'text' : 'password';
  });
});

// Email live format check
document.querySelectorAll('input[type="email"]').forEach(function(inp){
  inp.addEventListener('input', function(){
    const helper = inp.closest('.form-row')?.querySelector('.helper.email');
    if (!helper) return;
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
    if (inp.value && !emailRegex.test(inp.value)) {
      helper.textContent = 'Email format looks invalid';
    } else {
      helper.textContent = 'We will never share your email.';
    }
  });
});
