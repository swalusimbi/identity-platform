import nodemailer, { Transporter } from "nodemailer";
import { env } from "../utils/env";
import { AppError } from "../utils/errors";

export interface Mail {
  to: string;
  subject: string;
  text: string;
}

/** Mails captured by the memory provider, used by the test suite */
export const sentMails: Mail[] = [];

let transporter: Transporter | undefined;

function getTransporter(): Transporter {
  if (!env.SMTP_URL) {
    throw new Error("SMTP_URL is required when MAIL_PROVIDER is smtp");
  }
  // Bounded timeouts so a hanging SMTP server surfaces as a fast 502
  // here instead of an anonymous reverse proxy 504 upstream.
  transporter ??= nodemailer.createTransport({
    url: env.SMTP_URL,
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 15_000,
  });
  return transporter;
}

export async function sendMail(mail: Mail): Promise<void> {
  switch (env.MAIL_PROVIDER) {
    case "memory":
      sentMails.push(mail);
      return;

    case "smtp":
      try {
        await getTransporter().sendMail({ from: env.MAIL_FROM, ...mail });
      } catch (err) {
        console.error("SMTP delivery failed:", err);
        throw AppError.badGateway(
          "Email could not be sent right now, try again shortly",
          "MAIL_UNAVAILABLE"
        );
      }
      return;

    case "console":
      console.log(
        `✉ [mail] to=${mail.to} subject="${mail.subject}"\n${mail.text}`
      );
      return;
  }
}
