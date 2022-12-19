
$(document).on("click", ".book-modal-btn", function (e) {
    e.preventDefault()

    let url = $(this).attr("href");

    fetch(url)
        //.then(response => response.json())
        .then(response => response.text())
        .then(data => {
            console.log(data)
            //$(".modal-content .product-title").text(data.name)
            $("#quickModal .modal-dialog").html(data)
        })

    $("#quickModal").modal("show")

})

$(document).on("click", ".add-to-basket", function (e) {
    e.preventDefault();

    let url = $(this).attr("href");

    fetch(url)
        .then(response => {
            if (!response.ok) {
                alert("Mehsul bitib!")
            }
            return response.text();
        }).then(html => {
            $("#basket-block").html(html)
        })
})

//$(document).on('click', ".remove", function (e) {
//    e.preventDefault();

//    let url = $(this).attr("href");

//    fetch(url)
//        .then(response => {
//            if (response.ok) {
//                $(this).parent().parent().remove();
              
//            }
//        }
//        )
//})
