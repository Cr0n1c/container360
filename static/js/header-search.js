document.getElementById("header-container-search").addEventListener("keydown", function(e) {
    if (!e) { var e = window.event; }

    // Enter is pressed
    if (e.keyCode == 13) { submitFunction(); }
}, false);

function submitFunction(){
    var input = document.getElementById("header-container-search").value;
    var formatted = input.replace(":", "|");
    window.location.href = "/image?image_name=" + formatted;
}