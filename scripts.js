document.getElementById('poc').style.filter = 'blur(10px)';
function waitFor(variable, callback) {
    var interval = setInterval(function() {
        if(typeof variable !== 'undefined'){
            clearInterval(interval);
            callback();
        }
    }, 200);
}


async function getid(cve) {
    const api = "http://127.0.0.1:5000/";

    const response = await fetch(api + "utils/cve2id", {
        method: "GET",
        headers: {
            "cve": cve
        },
        mode: "cors"
    });

    if (!response.ok) {
        throw new Error("Something went wrong on API server!");
    }

    return await response.text();
}

function calcdgr(cvss) {
    if (cvss > 0.0 && cvss < 4.0) {return "Low"}
    else if (cvss > 3.9 && cvss < 7.0) {return "Medium"}
    else if (cvss > 6.9 & cvss < 9.0) {return "High"}
    else if (cvss > 8.9) {return "Critical"}
    else {return "?"};
}

function calcbc(cvss) {
    if (cvss > 0.0 && cvss < 4.0) {return "#26a269"}
    else if (cvss > 3.9 && cvss < 7.0) {return "#e5a50a"}
    else if (cvss > 6.9 & cvss < 9.0) {return "#c64600"}
    else if (cvss > 8.9) {return "#a51d2d"}
    else {return "#fff"};
}

async function search() {
    try {
        const prompt = document.getElementById("searchbar").value;

        const id = await getid(prompt);
        console.debug("ID:", id);

        const response = await fetch("http://127.0.0.1:5000/poc/data", {
            method: "GET",
            headers: {
                "poc-id": id
            },
            mode: "cors"
        });

        if (!response.ok) {
            throw new Error("Something went wrong on API server!");
        }

        const data = await response.json();
        console.debug(data);

        const response2 = await fetch("http://127.0.0.1:5000/poc/code", {
            method: "GET",
            headers: {
                "poc-id": id
            },
            mode: "cors"
        });

        if (!response2.ok) {
            throw new Error("Something went wrong on API server!");
        }

        const code = await response2.text();
        console.debug(code);

        var ir = ""
        if (data["isremote"] == "y") {ir="Yes"}
        else {ir="No"}
        var barcolor = await calcbc(data["cvss"]);
        var dgrlvl = await calcdgr(data["cvss"]);
        var cvss = data["cvss"].replace(".", "");

        document.getElementById("cve-name").innerHTML = " " + data["cve"];
        document.getElementById("type").innerHTML = " Type : " + data["type"];
        document.getElementById("ir").innerHTML = " Is remote? : " + ir;
        document.getElementById("progressBar").style.backgroundColor = barcolor;
        document.getElementById("progressBar").style.width = cvss + "%";
        document.getElementById("score").innerHTML = data["cvss"] + " | " + dgrlvl;
        document.getElementById("desc").innerHTML = data["desc"];
        document.getElementById("code").innerHTML = code;
        document.getElementById("dlbtn").href = data["dlpath"];
        document.getElementById('poc').style.transition = '0.5s';
        document.getElementById('poc').style.filter = 'none';
    } catch (error) {
        console.error(error);
    }
}
