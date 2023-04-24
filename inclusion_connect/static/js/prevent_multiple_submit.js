addEventListener("DOMContentLoaded", () => {
  // Prevent multiple submit client side.
  // Opt-in by adding a `js-prevent-multiple-submit` CSS class to a <form>.

  // Pay attention: in multi-step forms, the browser will remember the disabled
  // state of the button when clicking "Previous" in the browser, eventually
  // disabling moving forward afterwards!

  document.querySelectorAll('form.js-prevent-multiple-submit').forEach((form) => {
    let submitted = false;
    function disableSubmit(event) {
      if (submitted) {
        event.preventDefault();
      }
      submitted = true;
    }
    form.addEventListener("submit", disableSubmit);
  });
});
