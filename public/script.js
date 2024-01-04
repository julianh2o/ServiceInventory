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

    let modalService = null;

    $(".iconContainer img").click((e) => {
        const $el = $(e.target);
        modalService = $el.data("service");
        $(".modal-title").text(`Upload Icon: ${modalService}`);
        $('#uploadModal').modal("show");
    });

    $(".closeModal").click(() => {
        $('#uploadModal').modal("hide");
        $("#favicon").val(null);
    });

    $('#upload-form').submit(function(e) {
        e.preventDefault();

        let formData = new FormData();
        let fileInput = document.getElementById('favicon');
        let file = fileInput.files[0];
        formData.append('favicon', file);

        const [ip,port] = modalService.split(":");

        axios.post(`/hosts/${ip}/services/${port}/icon`, formData, {
            headers: {
                'Content-Type': 'multipart/form-data'
            }
        })
        .then(function (response) {
            const filename = response.data.filename;
            $(`img[data-service='${modalService}']`).attr("src",filename);
            $('#upload-status').html(`<p>File uploaded successfully. Filename: ${response.data.filename}</p>`);
            $('#uploadModal').modal("hide");
            $("#favicon").val(null);
        })
        .catch(function (error) {
            $('#upload-status').html(`<p>Error uploading file: ${error.message}</p>`);
        });
    });
});