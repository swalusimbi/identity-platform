import nodemailer, { Transporter } from "nodemailer";
import { env } from "../utils/env";

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
  transporter ??= nodemailer.createTransport(env.SMTP_URL);
  return transporter;
}

export async function sendMail(mail: Mail): Promise<void> {
  switch (env.MAIL_PROVIDER) {
    case "memory":
      sentMails.push(mail);
      return;

    case "smtp":
      await getTransporter().sendMail({ from: env.MAIL_FROM, ...mail });
      return;

    case "console":
      console.log(
        `✉ [mail] to=${mail.to} subject="${mail.subject}"\n${mail.text}`
      );
      return;
  }
}
