import { buildPutProfileBody, type PutProfileBody } from "./profilePut";
import type { Profile } from "./types";

export type ProfileUpdate =
  | Partial<Omit<PutProfileBody, "expectedRevision">>
  | ((current: Profile) => Partial<Omit<PutProfileBody, "expectedRevision">>);

/** Serialize edits from every panel in this browser, without sending stale fields.
 * The Gateway expects a complete PUT, so read the current profile inside the queue.
 * Rebase only across successful writes from this queue. External changes require
 * a reload; the database also checks the revision atomically at commit time.
 */
export function createProfileUpdater({
  read,
  write,
}: {
  read: (id: string) => Promise<Profile>;
  write: (id: string, body: PutProfileBody) => Promise<unknown>;
}) {
  const pending = new Map<string, Promise<void>>();
  const ownRevisions = new Map<string, number>();

  return (profile: Profile, changes: ProfileUpdate): Promise<void> => {
    const { id, revision } = profile;
    // Capture the submitted draft, including explicit nulls, before it is queued.
    const patch = typeof changes === "function" ? changes : structuredClone(changes);
    const operation = (pending.get(id) ?? Promise.resolve()).then(async () => {
      const current = await read(id);
      let expected = revision;
      while (expected < current.revision) {
        const next = ownRevisions.get(`${id}:${expected}`);
        if (next === undefined) break;
        expected = next;
      }
      if (expected !== current.revision) {
        throw new Error(
          "Profile changed in another window. Reload the profile before saving again.",
        );
      }
      await write(
        id,
        buildPutProfileBody(current, typeof patch === "function" ? patch(current) : patch),
      );
      ownRevisions.set(`${id}:${current.revision}`, current.revision + 1);
      // Bound history; very old drafts require a reload.
      if (ownRevisions.size > 128) ownRevisions.delete(ownRevisions.keys().next().value!);
    });
    // A rejected edit must not prevent a later edit or an explicit retry.
    const tail = operation.catch(() => {});
    pending.set(id, tail);
    void tail.then(() => {
      if (pending.get(id) === tail) pending.delete(id);
    });
    return operation;
  };
}
