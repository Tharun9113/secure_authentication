// static/js/script.js

document.addEventListener("DOMContentLoaded", function() {
    console.log("Page loaded!");

    // Disable submit button after click to prevent multiple submits
    const forms = document.querySelectorAll("form");

    forms.forEach(form => {
        form.addEventListener("submit", function(event) {
            const buttons = form.querySelectorAll("button");
            buttons.forEach(button => {
                button.disabled = true;
                button.innerText = "Processing...";
            });
        });
    });

    // Example: you can later add more interactivity like input validations here
});
