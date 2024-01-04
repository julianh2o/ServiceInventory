$(document).ready(() => {
    $(".edit").click(async (e) => {
        e.preventDefault();
        const $el = $(e.target).closest(".edit");
        const newValue = prompt(`Enter a new value for ${$el.data("key")} (${_.compact([$el.data("host"),$el.data("port")]).join(":")})`,$el.data("prev"))
        if (!newValue) return;
        if ($el.data("port")) {
            await axios.post(`/hosts/${$el.data("host")}/services/${$el.data("port")}/${$el.data("key")}`,newValue)
        } else {
            await axios.post(`/hosts/${$el.data("host")}/${$el.data("key")}`,newValue)
        }
        $el.text(newValue);
        $el.data("prev",newValue);
        $el.removeClass("bg-primary");
        $el.removeClass("bg-secondary");
        $el.removeClass("hideUntilHovered");
        $el.addClass("bg-success");
    });

    $(".toggle, .favorite").click(async (e) => {
        e.preventDefault();
        const $el = $(e.target).closest(".toggle,.favorite");
        const newValue = !$el.data("prev");
        if ($el.data("port")) {
            await axios.post(`/hosts/${$el.data("host")}/services/${$el.data("port")}/${$el.data("key")}`,newValue)
        } else {
            await axios.post(`/hosts/${$el.data("host")}/${$el.data("key")}`,newValue)
        }
        $el.data("prev",newValue);
        $el.removeClass("active");
        if (newValue) $el.addClass("active");
    });

    $(".showAll").click(async (e) => {
        e.preventDefault();
        const $el = $(e.target);
        $el.parent().find(".hideParent").addClass("showHidden");
        $el.hide();
    });
});