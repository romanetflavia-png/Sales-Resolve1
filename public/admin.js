document.addEventListener("DOMContentLoaded", async () => {
  const container = document.getElementById("messages");

  try {
    const res = await fetch("/api/messages");
    if (!res.ok) throw new Error("Eroare la fetch-ul mesajelor");
    
    const messages = await res.json();

    if (!messages || messages.length === 0) {
      container.innerHTML = "<p>Niciun mesaj primit încă.</p>";
      return;
    }

    let table = "<table><tr><th>Nume</th><th>Email</th><th>Mesaj</th><th>Data</th></tr>";
    messages.forEach(msg => {
      table += `<tr>
                  <td>${msg.name || "-"}</td>
                  <td>${msg.email || "-"}</td>
                  <td>${msg.message || "-"}</td>
                  <td>${msg.date || "-"}</td>
                </tr>`;
    });
    table += "</table>";

    container.innerHTML = table;
  } catch (err) {
    console.error(err);
    container.innerHTML = "<p>Eroare la încărcarea mesajelor.</p>";
  }
});
