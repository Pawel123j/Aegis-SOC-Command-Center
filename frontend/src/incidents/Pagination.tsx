export function Pagination({
  previous,
  hasNext,
  pending,
  onPrevious,
  onNext,
}: {
  previous: number;
  hasNext: boolean;
  pending: boolean;
  onPrevious: () => void;
  onNext: () => void;
}) {
  return (
    <div className="pagination">
      <span>Strona {previous + 1}</span>
      <div>
        <button type="button" disabled={!previous || pending} onClick={onPrevious}>
          Poprzednia
        </button>
        <button type="button" disabled={!hasNext || pending} onClick={onNext}>
          Następna
        </button>
      </div>
    </div>
  );
}
