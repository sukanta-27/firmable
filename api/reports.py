"""The eval reports the pipeline writes and the "How we know" page reads.

They live here, not in `pipeline/`, because the deployed image holds `api/` and the
published folder only; the pipeline imports them to write the same shape the app reads.
Plain Pydantic only: importing this module must not pull in FastAPI or DuckDB.
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ReportStamp(BaseModel):
    command: str
    ran_at: datetime
    code_version: str
    # Strategy and model names, reference versions and input hashes the numbers depend on.
    inputs: dict[str, str]


class Tally(BaseModel):
    right: int = 0
    missed: int = 0
    wrong: int = 0


class AttributionReport(BaseModel):
    stamp: ReportStamp
    strategy: str
    total: Tally
    by_case: dict[str, Tally]
    by_confidence: dict[str, Tally]


class KevDisagreement(BaseModel):
    item_id: str
    exploitation: str
    on_kev: bool


class EpssByAnswer(BaseModel):
    exploitation: str
    cves_with_epss: int
    median_epss: float | None


class ModelCheck(BaseModel):
    model: str
    statuses: dict[str, int]
    kev_both: int
    kev_model_only: int
    kev_only: int
    kev_neither: int
    kev_disagreements: list[KevDisagreement]
    epss_by_answer: list[EpssByAnswer]
    rdp_exposed_rank: int | None
    scored_exposures: int


class Disagreement(BaseModel):
    item_id: str
    reference: str
    other: str


class QuestionAgreement(BaseModel):
    question: str
    agree: int
    both_answered: int
    disagreements: list[Disagreement]


class ModelAgreement(BaseModel):
    reference: str
    other: str
    questions: list[QuestionAgreement]


class AnswersCheck(BaseModel):
    stamp: ReportStamp
    prompt_version: str
    answers_model: str
    kev_catalog_version: str | None
    epss_version: str | None
    models: list[ModelCheck]
    agreement: list[ModelAgreement]

    def lines(self) -> list[str]:
        if not self.models:
            return [f"no answers for prompt {self.prompt_version}"]
        out = [
            f"answers for prompt {self.prompt_version}; KEV {self.kev_catalog_version}; "
            f"EPSS {self.epss_version}"
        ]
        for m in self.models:
            out.append(f"\n== {m.model}")
            out += [f"  {status}: {n}" for status, n in m.statuses.items()]
            out.append(
                f"  KEV vs blind 'active' on CVE items: both {m.kev_both}, model only "
                f"{m.kev_model_only}, KEV only {m.kev_only}, neither {m.kev_neither}"
            )
            out += [
                f"    disagree: {d.item_id} model={d.exploitation} on_kev={d.on_kev}"
                for d in m.kev_disagreements
            ]
            out += [
                f"  median EPSS, blind {e.exploitation}: {e.median_epss} over "
                f"{e.cves_with_epss} CVEs"
                for e in m.epss_by_answer
            ]
            out.append(
                f"  rdp_exposed ranks {m.rdp_exposed_rank} of {m.scored_exposures} scored exposures"
            )
        for a in self.agreement:
            out.append(f"\n== agreement, {a.reference} vs {a.other}, items both answered")
            for q in a.questions:
                out.append(f"  {q.question}: {q.agree} of {q.both_answered} agree")
                out += [f"    {d.item_id}: {d.reference} vs {d.other}" for d in q.disagreements]
        return out


class ScorerCount(BaseModel):
    scorer: str
    ranked: int
    total: int


class RankPair(BaseModel):
    company_key: str
    company_name: str | None
    rank_first: int | None
    rank_second: int | None


class VictimMatch(BaseModel):
    # ransomware.live's terms ask that the source is named wherever the match is shown.
    source: Literal["Ransomware.live (https://www.ransomware.live)"]
    as_of: str
    victim_domains: int
    matched: int
    ranked: int
    companies: list[RankPair]


class RankingReport(BaseModel):
    stamp: ReportStamp
    file_id: str
    note: Literal["Illustration, not a measurement."]
    scorers: list[ScorerCount]
    first_scorer: str | None
    second_scorer: str | None
    top_100_shared: int | None
    biggest_moves: list[RankPair]
    victims: VictimMatch | None

    def lines(self) -> list[str]:
        out: list[str] = [self.note]
        out += [f"{s.scorer}: {s.ranked:,} of {s.total:,} companies ranked" for s in self.scorers]
        first, second = self.first_scorer, self.second_scorer
        if first is None or second is None:
            return out
        out.append(f"top 100 shared by {first} and {second}: {self.top_100_shared}")
        out.append(
            f"companies that move most, within either top 100 ({first} rank, {second} rank):"
        )
        out += [f"  {p.company_key}: {p.rank_first} vs {p.rank_second}" for p in self.biggest_moves]
        if self.victims:
            v = self.victims
            out.append(f"Source: {v.source}")
            out.append(
                f"ransomware.live victims (as of {v.as_of}, {v.victim_domains:,} victim "
                f"domains): {v.matched} are companies with a finding here, {v.ranked} of them "
                "ranked"
            )
            out += [f"  {p.company_key}: {p.rank_first} vs {p.rank_second}" for p in v.companies]
        return out


class UsageTotal(BaseModel):
    use_case: str
    model: str
    kind: Literal["messages", "count_tokens"]
    calls: int
    failures: int
    input_tokens: int
    output_tokens: int
    cache_write_tokens: int
    cache_read_tokens: int
    # The sum over priced calls only, None when none was priced; unpriced_calls says how
    # many it leaves out.
    cost_usd: float | None
    unpriced_calls: int
    median_seconds: float


class UsageReport(BaseModel):
    stamp: ReportStamp
    totals: list[UsageTotal]
