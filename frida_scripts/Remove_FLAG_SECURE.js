if (Java.available) {
  Java.perform(function () {
    var FLAG_SECURE = 0x00002000;
    try {
      var Window = Java.use('android.view.Window');
      Window.setFlags.overload('int','int').implementation = function (flags, mask) {
        flags = flags & ~FLAG_SECURE;
        mask  = mask  & ~FLAG_SECURE;
        return this.setFlags(flags, mask);
      };
    } catch (e) {}
    try {
      var Activity = Java.use('android.app.Activity');
      Activity.onResume.overload().implementation = function () {
        var r = this.onResume();
        try {
          var w = this.getWindow();
          var attrs = w.getAttributes();
          attrs.flags = attrs.flags & ~FLAG_SECURE;
          w.setAttributes(attrs);
        } catch (e) {}
        return r;
      };
    } catch (e) {}
  });
}
