"use strict";

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


  const pwInput = document.querySelector('.password-with-instructions input');
  if (pwInput) {
    function indicatorStatus(elt, matchesCrit, label) {
        elt.classList.toggle("ri-close-circle-line", !matchesCrit);
        elt.classList.toggle("text-warning", !matchesCrit);
        elt.classList.toggle("ri-checkbox-circle-line", matchesCrit);
        elt.classList.toggle("text-success", matchesCrit);
    }

    const pwLengthIndicator = document.getElementById("pw-length");
    const digitIndicator = document.getElementById("pw-digit");
    const lowerIndicator = document.getElementById("pw-lower");
    const upperIndicator = document.getElementById("pw-upper");
    const specialCharIndicator = document.getElementById("pw-special-char");

    pwInput.addEventListener("input", (event) => {
      const pw = event.target.value;

      const lengthOk = pw.length >= 12;
      indicatorStatus(pwLengthIndicator, lengthOk);

      const digitOk = /\d/.test(pw);
      indicatorStatus(digitIndicator, digitOk);

      const lowerOk = pw != pw.toUpperCase();
      indicatorStatus(lowerIndicator, lowerOk);

      const upperOk = pw != pw.toLowerCase();
      indicatorStatus(upperIndicator, upperOk);

      const specialCharOk = /(\W|_)/.test(pw);
      indicatorStatus(specialCharIndicator, specialCharOk);

      const fieldOk = lengthOk && digitOk && lowerOk && upperOk && specialCharOk;
      pwInput.classList.toggle("is-invalid", !fieldOk);
      pwInput.classList.toggle("is-valid", fieldOk);
    })
  }
});
