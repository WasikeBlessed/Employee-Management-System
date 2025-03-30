document.getElementById("resetForm").addEventListener("submit", async (e) => {
    e.preventDefault();

    const employeeID = document.getElementById("employeeID").value;
    const newPassword = document.getElementById("newPassword").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    const message = document.getElementById("message");

    try {
        const response = await fetch("/api/reset-password", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                employeeID,
                newPassword,
                confirmPassword,
            }),
        });

        const result = await response.json();

        if (response.ok) {
            message.textContent = result.message;
            message.className = "success";
            // Clear form after success
            document.getElementById("resetForm").reset();
        } else {
            message.textContent = result.error;
            message.className = "error";
        }
    } catch (error) {
        message.textContent = "An error occurred: " + error.message;
        message.className = "error";
    }
});