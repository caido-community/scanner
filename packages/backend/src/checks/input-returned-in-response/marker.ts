import { generateRandomString } from "engine";

export const createMarker = ({
  baselineBody,
  usedMarkers,
}: {
  baselineBody: string;
  usedMarkers: Set<string>;
}): string => {
  let marker = `scanner-${generateRandomString(8).toLowerCase()}`;
  let attempts = 0;

  while (
    (baselineBody.includes(marker) || usedMarkers.has(marker)) &&
    attempts < 5
  ) {
    marker = `scanner-${generateRandomString(8).toLowerCase()}`;
    attempts += 1;
  }

  usedMarkers.add(marker);
  return marker;
};
