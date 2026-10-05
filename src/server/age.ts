export const AGE_THRESHOLD = 20;

export interface BirthdateParts {
  year: number;
  month: number;
  day: number;
}

function isLeapYear(year: number): boolean {
  return year % 400 === 0 || (year % 4 === 0 && year % 100 !== 0);
}

function daysInMonth(year: number, month: number): number {
  if (month === 2) return isLeapYear(year) ? 29 : 28;
  if ([4, 6, 9, 11].includes(month)) return 30;
  return 31;
}

export function parseBirthdate(input: string): BirthdateParts {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(input);
  if (!m) throw new Error("birthdate must be YYYY-MM-DD");

  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  if (month < 1 || month > 12) throw new Error("birthdate has invalid month");
  if (day < 1 || day > daysInMonth(year, month)) throw new Error("birthdate has invalid day");

  return { year, month, day };
}

export function isOverAgeThreshold(birthdate: string, now = new Date(), threshold = AGE_THRESHOLD): boolean {
  const { year, month, day } = parseBirthdate(birthdate);
  const cutoffYear = now.getFullYear() - threshold;
  const cutoffMonth = now.getMonth() + 1;
  const cutoffDay = now.getDate();

  if (year !== cutoffYear) return year < cutoffYear;
  if (month !== cutoffMonth) return month < cutoffMonth;
  return day <= cutoffDay;
}
