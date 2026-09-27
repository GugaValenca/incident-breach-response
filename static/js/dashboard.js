// Same light UX touch as Project 2: auto-submit the filter form when a
// dropdown changes. The search field still waits for Enter/click so
// typing doesn't reload the page on every keystroke.
document.addEventListener("DOMContentLoaded", function () {
    var form = document.getElementById("filter-form");
    if (!form) return;

    form.querySelectorAll("select").forEach(function (field) {
        field.addEventListener("change", function () {
            form.submit();
        });
    });
});
