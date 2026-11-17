'use client';
export function ProjectList({ projects }: { projects: { id: string; name: string }[] }) {
  return <ul>{projects.map((p) => <li key={p.id}>{p.name}</li>)}</ul>;
}
