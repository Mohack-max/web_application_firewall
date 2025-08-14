// Medihack Base file 
const API_URL = "http://127.0.0.1:8080";

function postTest(data, headers = {}, resultId) {
    fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "text/plain", ...headers },
        body: data
    })
    .then(async res => {
        const text = await res.text();
        document.getElementById(resultId).innerHTML = `<b>Status:</b> ${res.status}<br><b>Response:</b> ${text}`;
    })
    .catch(err => {
        document.getElementById(resultId).innerHTML = `<span class='text-danger'>Error: ${err}</span>`;
    });
}

document.getElementById("sqli-form").onsubmit = e => {
    e.preventDefault();
    postTest(document.getElementById("sqli-input").value, {}, "sqli-result");
};
document.getElementById("xss-form").onsubmit = e => {
    e.preventDefault();
    postTest(document.getElementById("xss-input").value, {}, "xss-result");
};
document.getElementById("file-form").onsubmit = e => {
    e.preventDefault();
    const fileInput = document.getElementById("file-input");
    const file = fileInput.files[0];
    if (!file) {
        document.getElementById("file-result").innerHTML = "<span class='text-danger'>No file selected.</span>";
        return
    }
    const formData = new FormData();
    formData.append("file", file);
    fetch("http://127.0.0.1:8080/upload", {
        method: "POST",
        body: formData
    })
    .then(async res => {
        const text = await res.text();
        document.getElementById("file-result").innerHTML = `<b>Status:</b> ${res.status}<br><b>Response:</b> ${text}`;
    })
    .catch(err => {
        document.getElementById("file-result").innerHTML = `<span class='text-danger'>Error: ${err}</span>`;
    });
};
document.getElementById("header-form").onsubmit = e => {
    e.preventDefault();
    postTest("test", { "evil": document.getElementById("header-input").value }, "header-result");
};
document.getElementById("csrf-form").onsubmit = e => {
    e.preventDefault();
    postTest("test", { "x-csrf-token": document.getElementById("csrf-input").value }, "csrf-result");
};
document.getElementById("rate-form").onsubmit = e => {
    e.preventDefault();
    let count = 0;
    let result = "";
    function spam() {
        if (count < 7) {
            fetch(API_URL, { method: "POST", body: "rate test" })
                .then(async res => {
                    const text = await res.text();
                    result += `<b>Req ${count+1}:</b> Status ${res.status} - ${text}<br>`;
                    document.getElementById("rate-result").innerHTML = result;
                    count++;
                    spam();
                });
        }
    }
    spam();
};
