$(document).ready(function () {
    var SocialModel = can.Model.extend({
        findOne: "POST " + location_root + "social/{id}"
    },{});

    can.Component.extend({
        tag: "socialControls",
        template: can.view("#socialControlsStache"),
        viewModel: {
            hasCaptchaError: false,
            isAuthenticated: false,
            isFacebookEnabled: false,
            isGoogleEnabled: false,
            isTwitterEnabled: false,
            socialPicture: "",
            socialFirstName: "",
            socialLastName: "",
            social: new SocialModel(),
            updateSocial: function () {
                var viewModel = this;
                var values = {id: "sign_up"};
                values._xsrf = get_xsrf();
                SocialModel.findOne(values, function (social) {
                    if (social.authenticated) {
                        viewModel.attr("isAuthenticated", true);
                        viewModel.attr("socialPicture", social.picture);
                        viewModel.attr("socialFirstName", social.first_name);
                        viewModel.attr("socialLastName", social.last_name);
                        if($("#userEmail").length) {
                            if(!$("#userEmail").val()){
                                $("#userEmail").val(social.email);
                            }
                        }
                    }
                    if(social.google.enabled) {
                        viewModel.attr("isGoogleEnabled", true);
                    }
                });
            },
        },
        events: {
            "inserted": function () {
                this.viewModel.updateSocial();
            },
            "#googleOauth click": function() {
                window.document.location = location_root + "google/oauth2";
            },
            "#refresh_captcha click": function(event) {
                this.viewModel.refreshCaptcha();
            },
            "#signinLink click": function(event) {
                window.document.location = location_root + "sign_in";
            },
            "#login_form submit": function(event) {
                return false;
            }
        }
    });

    $("#socialControls").html(
        can.stache("<socialControls></socialControls>")());
});