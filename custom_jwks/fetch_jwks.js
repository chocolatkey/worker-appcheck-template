const errors = require("jose/dist/browser/util/errors");

module.exports = async (url, timeout) => {
    let controller, id;
    let timedOut = false;
    if (typeof AbortController === "function") {
        // eslint-disable-next-line no-undef
        controller = new AbortController();
        id = setTimeout(() => {
            timedOut = true;
            controller.abort();
        }, timeout);
    }

    const response = await fetch(url.href, {
        signal: controller ? controller.signal : undefined,
        redirect: "manual",
        method: "GET",
        cf: {
            cacheTtlByStatus: { "200-299": 21600, 404: 1, "500-599": 0 } // THE IMPORTANT PART: cache for up to 6h
        }
    }).catch((err) => {
        if (timedOut) throw new errors.JWKSTimeout();
        throw err;
    });

    if (id !== undefined) clearTimeout(id);

    if (response.status !== 200) {
        throw new errors.JOSEError("Expected 200 OK from the JSON Web Key Set HTTP response");
    }

    try {
        return await response.json();
    } catch {
        throw new errors.JOSEError("Failed to parse the JSON Web Key Set HTTP response as JSON");
    }
};