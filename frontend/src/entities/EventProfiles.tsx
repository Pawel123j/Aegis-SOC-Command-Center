import { Badge, ErrorNotice, Loading } from '../components';
import type { SecurityEvent } from '../types';
import { eventEntityParams } from './filters';
import { IndexNotice } from './presentation';
import { entityKinds } from './labels';
import type { EntityPage, EntitySummary } from './types';
import { useEntityResource } from './useEntityResource';
import './entities.css';

export function EventProfiles({
  event,
  onProfile,
}: {
  event: SecurityEvent;
  onProfile: (id: string) => void;
}) {
  const params = eventEntityParams(event);
  const resource = useEntityResource<EntityPage<EntitySummary>>(
    params ? `/entities/by-event/${encodeURIComponent(event.event_id)}?${params}` : null,
  );
  return (
    <section className="entity-event-links" aria-label="Profile tego zdarzenia">
      <h3>Profile tego zdarzenia</h3>
      <p className="muted">
        Otwórz profil ustalony z zachowanego dowodu. Przyciski pól powyżej nadal służą do
        wyszukiwania zdarzeń.
      </p>
      {!params && <p className="muted">Profile wymagają przeszłego czasu zdarzenia.</p>}
      <ErrorNotice error={resource.error} />
      {resource.pending && <Loading />}
      {resource.data && (
        <>
          <IndexNotice status={resource.data.index_status} />
          {resource.data.items.length ? (
            <div className="button-row">
              {resource.data.items.map((item) => (
                <button key={item.id} onClick={() => onProfile(item.id)}>
                  <Badge>{entityKinds[item.kind]}</Badge> {item.label}
                </button>
              ))}
            </div>
          ) : (
            <p className="muted">
              {resource.data.index_status.complete
                ? 'W tym dowodzie nie znaleziono identyfikatorów profili.'
                : 'Profile pojawią się po uzupełnieniu indeksu.'}
            </p>
          )}
        </>
      )}
    </section>
  );
}
