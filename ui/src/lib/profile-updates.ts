import { buildPutProfileBody, type PutProfileBody } from "./profilePut";
import type { Profile } from "./types";

export type ProfileUpdate =
  | Partial<PutProfileBody>
  | ((current: Profile) => Partial<PutProfileBody>);

/** Serialize edits from every panel in this browser, without sending stale fields.
 * The Gateway expects a complete PUT, so read the current profile inside the queue.
 * This is not cross-client optimistic locking; other clients can still edit profiles.
 */
export function createProfileUpdater({
  read,
  write,
}: {
  read: (id: string) => Promise<Profile>;
  write: (id: string, body: PutProfileBody) => Promise<unknown>;
}) {
  const pending = new Map<string, Promise<void>>();

  return (id: string, changes: ProfileUpdate): Promise<void> => {
    // Capture the submitted draft, including explicit nulls, before it is queued.
    const patch = typeof changes === "function" ? changes : structuredClone(changes);
    const operation = (pending.get(id) ?? Promise.resolve()).then(async () => {
      const current = await read(id);
      await write(
        id,
        buildPutProfileBody(current, typeof patch === "function" ? patch(current) : patch),
      );
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
