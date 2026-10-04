import { buildPutProfileBody, type PutProfileBody } from "./profilePut";
import type { Profile } from "./types";

export type ProfileUpdate =
  | Partial<Omit<PutProfileBody, "expectedRevision">>
  | ((current: Profile) => Partial<Omit<PutProfileBody, "expectedRevision">>);

export type ProfileRevision = Pick<Profile, "id" | "revision">;
export type ProfileWriteQueue = (
  profile: ProfileRevision,
  write: (current: Profile) => Promise<unknown>,
) => Promise<void>;

/** All profile endpoints share one revision history and write queue. External
 * changes require a reload; successful local writes can rebase later drafts.
 */
export function createProfileWriteQueue({
  read,
}: {
  read: (id: string) => Promise<Profile>;
}): ProfileWriteQueue {
  const pending = new Map<string, Promise<void>>();
  const ownRevisions = new Map<string, number>();
  return ({ id, revision }, write) => {
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
      await write(current);
      ownRevisions.set(`${id}:${current.revision}`, current.revision + 1);
      if (ownRevisions.size > 128) ownRevisions.delete(ownRevisions.keys().next().value!);
    });
    const tail = operation.catch(() => {});
    pending.set(id, tail);
    void tail.then(() => {
      if (pending.get(id) === tail) pending.delete(id);
    });
    return operation;
  };
}

export function createProfileUpdater({
  read,
  write,
  queue = createProfileWriteQueue({ read }),
}: {
  read: (id: string) => Promise<Profile>;
  write: (id: string, body: PutProfileBody) => Promise<unknown>;
  queue?: ProfileWriteQueue;
}) {
  return (profile: Profile, changes: ProfileUpdate): Promise<void> => {
    const { id } = profile;
    const patch = typeof changes === "function" ? changes : structuredClone(changes);
    return queue(profile, (current) =>
      write(id, buildPutProfileBody(current, typeof patch === "function" ? patch(current) : patch)),
    );
  };
}
