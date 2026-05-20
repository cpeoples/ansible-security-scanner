document.addEventListener("DOMContentLoaded", function () {
  var links = document.querySelectorAll("#R-body a, #R-main-content a, .R-article-content a");
  links.forEach(function (link) {
    var href = link.getAttribute("href");
    if (href && (href.startsWith("http://") || href.startsWith("https://"))) {
      var currentDomain = window.location.hostname;
      var linkDomain = new URL(href).hostname;
      if (linkDomain !== currentDomain) {
        link.setAttribute("target", "_blank");
        link.setAttribute("rel", "noopener noreferrer");
      }
    }
  });
});
