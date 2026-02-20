import { type EditorView } from "@codemirror/view";

export function getSelectedRequestFromDOM() {
  const requestEditor = document.querySelector("[data-language='http-request']");

  if (requestEditor === null) {
    return undefined;
  }

  if (!(requestEditor instanceof HTMLElement)) {
    return undefined;
  }

  let view = (requestEditor as unknown as { cmView?: EditorView }).cmView;
  if (view === undefined) {
    const cmEditor = requestEditor.querySelector(".cm-editor");
    if (cmEditor instanceof HTMLElement) {
      view = (cmEditor as unknown as { cmView?: EditorView }).cmView;
    }
  }

  if (view === undefined) {
    return undefined;
  }

  const rawRequest = view.state.doc.toString();
  const lines = rawRequest.split("\n");
  const firstLine = lines[0]?.trim();

  if (firstLine === undefined || firstLine === "") {
    return undefined;
  }

  const parts = firstLine.split(" ");
  const pathAndQuery: string = parts[1] ?? "/";
  const [path] =
    pathAndQuery.includes("?") === true
      ? pathAndQuery.split("?")
      : [pathAndQuery, ""];

  const hostLine = lines.find((line: string) =>
    line.toLowerCase().startsWith("host:"),
  );
  const hostFromRequest =
    hostLine !== undefined
      ? hostLine.split(":").slice(1).join(":").trim()
      : undefined;

  let requestId: string | undefined;

  if (hostFromRequest !== undefined && path !== undefined && path !== "") {
    const allRows = Array.from(document.querySelectorAll(".c-item-row"));

    for (const row of allRows) {
      const hostCell = row
        .querySelector("[data-column-id='REQ_HOST']")
        ?.textContent?.trim();
      const pathCell = row
        .querySelector("[data-column-id='REQ_PATH']")
        ?.textContent?.trim();
      const rowId = row.getAttribute("data-row-id");

      if (
        hostCell !== undefined &&
        hostCell !== "" &&
        hostCell.includes(hostFromRequest) &&
        pathCell === path &&
        rowId !== null &&
        rowId !== ""
      ) {
        requestId = rowId;
        break;
      }
    }
  }

  let url: string | undefined;

  if (hostLine !== undefined) {
    const host = hostLine.split(":").slice(1).join(":").trim();
    url = `https://${host}`;
  } else {
    return undefined;
  }

  try {
    const urlObj = new URL(url);
    const [finalPath, query = ""] =
      pathAndQuery.includes("?") === true
        ? pathAndQuery.split("?")
        : [pathAndQuery, ""];

    const hostMatch = rawRequest.match(/Host:\s*(.+?)(?::(\d+))?\r?\n/i);
    const hostFromMatch = hostMatch?.[1]?.trim();
    const host =
      hostFromMatch !== undefined && hostFromMatch !== ""
        ? hostFromMatch
        : urlObj.hostname;
    const portFromMatch = hostMatch?.[2];
    const port =
      portFromMatch !== undefined
        ? parseInt(portFromMatch)
        : urlObj.port !== ""
          ? parseInt(urlObj.port)
          : urlObj.protocol === "https:"
            ? 443
            : 80;

    const finalIdValue = requestId ?? Date.now().toString();
    const finalPathValue =
      finalPath !== undefined && finalPath !== "" ? finalPath : "/";

    return {
      id: finalIdValue,
      host,
      port,
      path: finalPathValue,
      query,
    };
  } catch {
    return undefined;
  }
}
