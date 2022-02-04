$(document).ready(function() {
  const NavY = $('#nav').offset().top;
  const stickyNav = function(){
    const ScrollY = $(window).scrollTop();
    if (ScrollY > NavY) {
      $('#nav').addClass('sticky');
    } else {
      $('#nav').removeClass('sticky');
    }
  };
  stickyNav();
  $(window).scroll(function() {
    stickyNav();
  });
});
