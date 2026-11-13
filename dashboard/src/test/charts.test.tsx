import { fireEvent, render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { TrendChart } from "../components/charts";

it("retains a valid selection when a refreshed trend contains fewer days", () => {
  const series = [{ key: "events", label: "رویداد", color: "#5ad6b7" }];
  const data = [{ date: "2026-11-11", events: 1 }, { date: "2026-11-12", events: 2 }];
  const page = render(<TrendChart data={data} series={series} />);
  const days = screen.getAllByRole("button").filter((el) => el.tagName.toLowerCase() === "g");
  fireEvent.focus(days[1]);
  page.rerender(<TrendChart data={[data[0]]} series={series} />);
  expect(screen.getByRole("img")).toBeInTheDocument();
  expect(screen.getByText("۱", { selector: "b" })).toBeInTheDocument();
});
