export function getSelectedRequestFromDOM() {
  const requestEditor = document.querySelector(
    "[data-language='http-request']"
  ) as HTMLElement;

  if (!requestEditor) {
    return null;
  }

  const rawRequest = requestEditor.innerText;
  const lines = rawRequest.split("\n");
  const firstLine = lines[0]?.trim();

  if (!firstLine) {
    return null;
  }

  const parts = firstLine.split(" ");
  const pathAndQuery = parts[1] || "/";
  const [path] = pathAndQuery.includes("?")
    ? pathAndQuery.split("?")
    : [pathAndQuery, ""];

  const hostLine = lines.find((line) => line.toLowerCase().startsWith("host:"));
  const hostFromRequest = hostLine
    ? hostLine.split(":").slice(1).join(":").trim()
    : null;

  let requestId: string | undefined;

  if (hostFromRequest && path) {
    const allRows = Array.from(document.querySelectorAll(".c-item-row"));

    for (const row of allRows) {
      const hostCell = row
        .querySelector("[data-column-id='REQ_HOST']")
        ?.textContent?.trim();
      const pathCell = row
        .querySelector("[data-column-id='REQ_PATH']")
        ?.textContent?.trim();
      const rowId = row.getAttribute("data-row-id");

      if (hostCell?.includes(hostFromRequest) && pathCell === path && rowId) {
        requestId = rowId;
        break;
      }
    }
  }

  let url: string | null = null;

  if (hostLine) {
    const host = hostLine.split(":").slice(1).join(":").trim();
    url = `https://${host}`;
  } else {
    return null;
  }

  try {
    const urlObj = new URL(url);
    const [finalPath, query = ""] = pathAndQuery.includes("?")
      ? pathAndQuery.split("?")
      : [pathAndQuery, ""];

    const hostMatch = rawRequest.match(/Host:\s*(.+?)(?::(\d+))?\r?\n/i);
    const host = hostMatch?.[1]?.trim() || urlObj.hostname;
    const port = hostMatch?.[2]
      ? parseInt(hostMatch[2])
      : urlObj.port
        ? parseInt(urlObj.port)
        : urlObj.protocol === "https:"
          ? 443
          : 80;

    return {
      id: requestId || Date.now().toString(),
      host,
      port,
      path: finalPath || "/",
      query,
    };
  } catch {
    return null;
  }
}

