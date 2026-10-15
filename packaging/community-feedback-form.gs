// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Platten Industries. Separate commercial licensing is available; see COMMERCIAL.md.

/**
 * Builds the SPLAT community test feedback form and its response spreadsheet.
 *
 * What testers do is defined by docs/COMMUNITY-TESTING.md. Every section below maps to a part of
 * that guide, and this file is the reviewable, rebuildable form of the survey: a form clicked
 * together by hand can be neither diffed nor rebuilt. It asks; it claims nothing.
 *
 * Run once, from the Google account that should own the form:
 *   1. script.google.com -> New project -> paste this file over Code.gs.
 *   2. Set CONFIG.followUpContact. Nothing else needs changing.
 *   3. Run createCommunityFeedbackForm and approve the two permissions it asks for (Google Forms
 *      and Google Sheets). It needs no Drive, mail or network access.
 *   4. Read the links from the execution log. Sharing the respondent link is a separate decision.
 *   5. Acceptance: submit one response with a malformed hash and confirm it is refused, submit one
 *      valid response and confirm it lands in the sheet, then delete that row.
 *
 * Never commit the form's links or IDs: the repository is public, and the edit link is the key.
 */

const CONFIG = {
  // Left blank on purpose. It is the address testers use for private reports, only the operator can
  // choose it, and the script refuses to run without it rather than publish "report to undefined".
  followUpContact: '',
  // Off by default. A form that collects addresses has to say why, and the script checks that it does.
  collectEmail: false,
  emailReason: '',
};

// One place for the package, so a rebuilt installer is a one-line change here. The build record
// (docs/audits/*-community-installer-build.md) is where this hash is authoritative.
const PACKAGE = {
  version: '0.2.0',
  file: 'SPLAT-Community-0.2.0-Setup.exe',
  sha256: '33d2c7bb8d0885ec5bed1f4ecaabaa7bf21ef078b231b6947b02d72ffcc39436',
  // Resolves only once docs/COMMUNITY-TESTING.md is on main. Open it before sharing the form.
  guideUrl: 'https://github.com/Spplatten/SPLAT/blob/main/docs/COMMUNITY-TESTING.md',
};

const PRIVACY =
  'Do not paste tokens, agent.token, keys, passwords, usernames, hostnames, IP addresses or file ' +
  'paths that contain a username.';
const CONTACT_NOTE =
  'This is the only box where contact details belong. Leave it empty if you would rather not be ' +
  'contacted. Do not paste tokens, keys or passwords.';

const FORM_ID_PROPERTY = 'communityFeedbackFormId';
// Sections 2-6 plus the two branch pages. Changing the structure should mean changing this on purpose.
const EXPECTED_PAGE_BREAKS = 7;

// The clean-machine matrix and the protocol list, as COMMUNITY-TESTING.md words them.
const INSTALL_ROWS = [
  'First install',
  'Repeat install over an existing install',
  'Upgrade refused while the console is running',
  'Missing WSL handled cleanly',
  'Missing BPF-LSM handled cleanly',
  'Wrong rootfs hash refused',
  'Existing distro name refused',
  'Failed bootstrap handled cleanly',
  'Uninstall',
  'Unrelated distros and operator data survived',
];
const PROTOCOL_ROWS = [
  'Wrong secret refused',
  'Fake daemon that can receive only the initial nonce',
  'Replayed request refused on the same connection',
  'Replayed request refused on a fresh connection',
  'Sequence gap refused',
  'Altered authenticated frame refused',
  'Truncated frame refused',
  'Oversized frame refused',
  'Client disconnect handled',
  'Lease expiry enforced',
  'Concurrent leases isolated',
  'Permitted request accepted (positive control)',
];
const PASS_FAIL = ['Pass', 'Fail', 'Not tried'];

/** Creates the form and its response sheet. Run once. */
function createCommunityFeedbackForm() {
  assertConfigured_();
  const props = PropertiesService.getScriptProperties();
  if (props.getProperty(FORM_ID_PROPERTY)) {
    throw new Error(
      'A form from an earlier run already exists. Run printLinks to find it, or forgetPreviousForm ' +
      'to allow a second one.');
  }

  const form = FormApp.create('SPLAT community test candidate ' + PACKAGE.version + ' - tester feedback');
  let sheet = null;
  try {
    sheet = SpreadsheetApp.create('SPLAT community feedback ' + PACKAGE.version + ' - responses');
    configure_(form);
    const built = build_(form);
    form.setDestination(FormApp.DestinationType.SPREADSHEET, sheet.getId());
    audit_(form, built);
    // Recorded only after the audit, so a failed build never blocks the rerun that fixes it.
    props.setProperty(FORM_ID_PROPERTY, form.getId());
  } catch (e) {
    Logger.log('The build failed part-way. Delete these before running again: ' + form.getEditUrl() +
      (sheet ? ' and ' + sheet.getUrl() : ''));
    throw e;
  }
  printLinks();
}

/** Logs the links of the form this project created. */
function printLinks() {
  const id = PropertiesService.getScriptProperties().getProperty(FORM_ID_PROPERTY);
  if (!id) {
    throw new Error('This project has not created a form.');
  }
  const form = FormApp.openById(id);
  Logger.log('Respondent link (share it only once you have decided where): ' + form.getPublishedUrl());
  Logger.log('Edit link (owner only; never share or commit): ' + form.getEditUrl());
  Logger.log('Responses sheet (owner only): ' + SpreadsheetApp.openById(form.getDestinationId()).getUrl());
}

/** Lets createCommunityFeedbackForm run again. Deletes nothing: the old form stays in Drive. */
function forgetPreviousForm() {
  PropertiesService.getScriptProperties().deleteProperty(FORM_ID_PROPERTY);
}

function assertConfigured_() {
  const problems = [];
  if (!CONFIG.followUpContact.trim()) {
    problems.push('CONFIG.followUpContact is blank. It is the address testers use for private reports.');
  }
  if (CONFIG.collectEmail && !CONFIG.emailReason.trim()) {
    problems.push('CONFIG.collectEmail is true but CONFIG.emailReason is blank. A form that collects addresses must say why.');
  }
  if (!/^[0-9a-f]{64}$/.test(PACKAGE.sha256)) {
    problems.push('PACKAGE.sha256 is not 64 lowercase hexadecimal characters.');
  }
  if (problems.length) {
    throw new Error(problems.join('\n'));
  }
}

function configure_(form) {
  const contact = CONFIG.followUpContact.trim();
  form.setDescription(describe_());
  form.setCollectEmail(CONFIG.collectEmail);
  // A response limit is enforced by requiring a Google sign-in, and nobody should have to sign in
  // to Google to tell us the installer failed.
  form.setLimitOneResponsePerUser(false);
  form.setProgressBar(true);
  form.setConfirmationMessage(
    'Thank you. If you found a possible security issue, please also report it privately to ' + contact + '.');
}

function describe_() {
  const email = CONFIG.collectEmail
    ? 'This form collects your email address, because ' + CONFIG.emailReason.trim()
    : 'This form does not collect your email address.';
  return [
    'Feedback on the SPLAT community test candidate ' + PACKAGE.version + ' (' + PACKAGE.file + ').',
    'Installer SHA-256: ' + PACKAGE.sha256,
    '',
    'This candidate is UNSIGNED and is not release-ready. A checksum is not publisher authentication, ' +
      'and its clean-machine acceptance matrix has not yet passed. Run it only on an isolated test ' +
      'machine or virtual machine.',
    '',
    'What to run, and what each answer means: ' + PACKAGE.guideUrl,
    '',
    'Privacy: there are no file uploads, and the form asks for verdicts rather than raw output. ' +
      PRIVACY + ' Raw probe records contain account IDs and machine details; share them privately, ' +
      'and only if you choose to.',
    '',
    'A possible security issue goes to ' + CONFIG.followUpContact.trim() + ' as well as into this form.',
    email,
    'Responses are read by Platten Industries. A name or handle you give may be credited in the public test record.',
  ].join('\n');
}

/**
 * Adds every question. Returns the ids the audit needs. Branch targets are wired last, because a
 * choice can only point at a page break that already exists.
 */
function build_(form) {
  const personal = [];
  const contact = CONFIG.followUpContact.trim();

  // ---- Section 1: package identity (page one has no page break above it) ----------------------
  form.addSectionHeaderItem()
    .setTitle('Section 1 of 6 - Package identity')
    .setHelpText('These answers tie every other answer to the exact file you ran.');

  const hash = shortText_(form, 'Installer SHA-256 that you computed',
    'Compute it yourself with: Get-FileHash -Algorithm SHA256 .\\' + PACKAGE.file + '\n' +
    'Enter the 64 hexadecimal characters with no spaces. Do not copy it from this page.',
    {
      required: true,
      // TextItem has no getValidation, so the audit cannot read this back. The acceptance step that
      // submits a malformed hash is the check for it.
      validation: FormApp.createTextValidation()
        .setHelpText('Enter exactly 64 hexadecimal characters (0-9, a-f) and nothing else.')
        .requireTextMatchesPattern('^[0-9a-fA-F]{64}$')
        .build(),
    });
  choice_(form, 'Did it match the checksum published for ' + PACKAGE.file + '?',
    'Compare what you computed with the checksum named at the top of this form.',
    ['Yes, it matched', 'No, it did not match', 'I did not check'], true);
  choice_(form, 'Did the package verifier pass over the install folder?',
    'Run: powershell -ExecutionPolicy Bypass -File "<install dir>\\packaging\\verify-community-package.ps1" ' +
    '-PackagePath "<install dir>"\nIt prints a verdict of PASS, or one FAIL line per problem. A pass ' +
    'shows the files match the package\'s own records; it does not authenticate the publisher.',
    ['PASS', 'FAIL', 'Not run'], true);
  paragraph_(form, 'If it failed: the FAIL lines it printed',
    'Paste only the FAIL lines. Leave this empty if it passed.', {});

  // ---- Section 2: machine ---------------------------------------------------------------------
  form.addPageBreakItem()
    .setTitle('Section 2 of 6 - Your machine')
    .setHelpText('Versions only. Nothing here needs a computer name or an account name.');
  shortText_(form, 'Windows edition and build',
    'For example: Windows 11 Pro 26200 (shown by winver).', { required: true });
  shortText_(form, 'WSL version',
    'Paste only the "WSL version:" line from: wsl --version\nType "not installed" if WSL is absent.',
    { required: true });
  shortText_(form, 'Kernel version inside WSL',
    'The output of: uname -r\nFor example 6.18.33.2-microsoft-standard-WSL2. Leave empty if WSL is absent.', {});
  choice_(form, 'Is BPF-LSM active?',
    'Yes means "bpf" appears in the output of: cat /sys/kernel/security/lsm',
    ['Yes', 'No', 'I did not check'], true);
  choice_(form, 'What kind of machine was this?', '',
    ['A clean machine', 'A disposable virtual machine', 'My daily-use machine'], true);
  choice_(form, 'Which Windows account ran the installer and the tests?',
    'The account you were signed in as, not whether you chose "Run as administrator".',
    ['A standard user', 'An administrator'], true);

  // ---- Section 3: installation ----------------------------------------------------------------
  form.addPageBreakItem()
    .setTitle('Section 3 of 6 - Installation')
    .setHelpText(
      'One row per item in "Installer acceptance on a clean machine" in COMMUNITY-TESTING.md.\n' +
      'Pass: it behaved as that guide describes. For a refusal case, Pass means it refused cleanly ' +
      'and changed nothing it should not have.\nFail: it did something else.\nNot tried: you did not run it.');
  grid_(form, 'Installation checklist', '', INSTALL_ROWS, PASS_FAIL);
  choice_(form, 'Did SmartScreen or antivirus block the installer?',
    'The installer is unsigned, so a warning is expected.',
    ['Yes, and I continued', 'Yes, and I stopped', 'No'], true);
  choice_(form, 'Did the console open, and did every page load?', '',
    ['Yes, every page loaded', 'Some pages failed', 'It did not open'], true);
  paragraph_(form, 'Anything that failed, in your words',
    'What you did, what you expected and what happened. Leave empty if nothing failed.', {});
  // Last on its page: a page's branch is decided by its final question.
  const protocolGate = choice_(form, 'Did you also run the loopback protocol tests?',
    'The next section. It is optional.',
    ['Yes, some or all of them', 'No, skip them'], true);

  // ---- Section 4: loopback protocol tests (optional) ------------------------------------------
  const pProtocol = form.addPageBreakItem()
    .setTitle('Section 4 of 6 - Loopback protocol tests')
    .setHelpText(
      'Use an isolated test machine.\nPass: the hostile input was refused, or the positive control was ' +
      'accepted, as COMMUNITY-TESTING.md describes.\nFail: it was not.\nNot tried: you did not run it.');
  grid_(form, 'Protocol tests', '', PROTOCOL_ROWS, PASS_FAIL);
  const launchGate = choice_(form, 'Did you observe any unauthorized workload launch or unauthorized output?',
    'The result that matters most. Answer Yes only if a hostile input caused a workload to run or produced output.',
    ['No, zero of either', 'Yes'], true);

  const pReport = form.addPageBreakItem()
    .setTitle('Section 4 - A possible vulnerability')
    .setHelpText(
      'An unauthorized launch or output is a security finding. Please report it privately to ' + contact +
      ' as well. Do not put reproduction steps, tokens or host data in this form.');
  paragraph_(form, 'Which test, and what happened, in one or two sentences',
    'Keep the detail for the private report.', {});

  // ---- Section 5: second-account registration measurement (optional) -------------------------
  const pRowGate = form.addPageBreakItem()
    .setTitle('Section 5 of 6 - Row 2.4 registration measurement')
    .setHelpText(
      'The ten-minute measurement in COMMUNITY-TESTING.md. It is optional. Verdicts only: do not paste ' +
      'the raw records, which contain account IDs and machine details.');
  const rowGate = choice_(form, 'Did you run the registration measurement?', '',
    ['Yes', 'No, skip it'], true);

  const pRowDetail = form.addPageBreakItem()
    .setTitle('Section 5 - Registration verdicts')
    .setHelpText('Verdicts only.');
  choice_(form, 'Were the owner and the operator both standard local accounts?',
    'The guide asks for two distinct standard accounts. A filtered administrator does not establish the boundary.',
    ['Both were standard accounts', 'One or both were administrators', 'I am not sure'], true);
  choice_(form, 'Did your own-distro control open as root in the operator session?', '',
    ['Yes', 'No', 'Did not run'], true);
  choice_(form, 'From the operator session, what did the owner\'s registration do?',
    'Absent means the error WSL_E_DISTRO_NOT_FOUND.',
    ['Absent (WSL_E_DISTRO_NOT_FOUND)', 'Visible', 'Did not run'], true);
  choice_(form, 'Did the owner-side connection control succeed?',
    'A listener answering its own owner is the control. Without it, a failure from the operator session means nothing.',
    ['Yes', 'No', 'Did not run'], true);
  choice_(form, 'From the operator session, what answered on that port?',
    'An open port alone does not show that it belongs to the other account.',
    ['The owner\'s listener, with its marker', 'The port opened but no marker came back',
      'The connection was refused or timed out', 'I did not measure this'], true);
  choice_(form, 'Will you share the raw owner and operator records privately, if asked?',
    'Do not paste them here.', ['Yes', 'No'], true);

  // ---- Section 6: overall ---------------------------------------------------------------------
  const pOverall = form.addPageBreakItem().setTitle('Section 6 of 6 - Overall');
  scale_(form, 'How clear were the install instructions?', 'Not at all clear', 'Completely clear');
  scale_(form, 'How confident are you that the package you ran is the one that was published?',
    'Not at all confident', 'Completely confident');
  paragraph_(form, 'What should change before a wider release?', '', {});
  personal.push(shortText_(form, 'A name or handle to credit you in the test record',
    'Optional. Leave empty to stay anonymous.', {}).getId());
  personal.push(form.addCheckboxItem()
    .setTitle('Follow-up')
    .setHelpText('Optional.')
    .setChoiceValues(['You may contact me about my answers'])
    .setRequired(false)
    .getId());
  personal.push(shortText_(form, 'How to reach you',
    'Optional. Only used if you ticked the box above.', { warning: CONTACT_NOTE }).getId());

  // ---- Branches -------------------------------------------------------------------------------
  // Skipping an optional section lands on the next gate or on the overall section, never past it.
  route_(protocolGate, [pProtocol, pRowGate]);
  route_(launchGate, [pRowGate, pReport]);
  route_(rowGate, [pRowDetail, pOverall]);

  return { personal: personal, hashId: hash.getId() };
}

/**
 * Checks the finished form against the rules in the survey handoff (private/ since 2026-10-14), reading
 * the form back rather than trusting the code that built it. Throws, and the caller leaves the
 * form unrecorded so it can be deleted.
 */
function audit_(form, built) {
  const problems = [];

  if (form.collectsEmail() !== CONFIG.collectEmail) {
    problems.push('The form\'s email collection does not match CONFIG.collectEmail.');
  }
  if (form.getItems(FormApp.ItemType.FILE_UPLOAD).length > 0) {
    problems.push('The form has a file-upload question.');
  }
  const pageBreaks = form.getItems(FormApp.ItemType.PAGE_BREAK).length;
  if (pageBreaks !== EXPECTED_PAGE_BREAKS) {
    problems.push('The form has ' + pageBreaks + ' page breaks, expected ' + EXPECTED_PAGE_BREAKS + '.');
  }

  // Every free-text box carries a warning.
  const boxes = [].concat(
    form.getItems(FormApp.ItemType.TEXT).map(function (i) { return i.asTextItem(); }),
    form.getItems(FormApp.ItemType.PARAGRAPH_TEXT).map(function (i) { return i.asParagraphTextItem(); }));
  boxes.forEach(function (box) {
    const help = box.getHelpText();
    if (help.indexOf(PRIVACY) === -1 && help.indexOf(CONTACT_NOTE) === -1) {
      problems.push('The free-text question "' + box.getTitle() + '" has no privacy warning.');
    }
  });

  // No required personal fields.
  built.personal.forEach(function (id) {
    const item = form.getItemById(id);
    if (item === null || requirable_(item).isRequired()) {
      problems.push('A personal field is missing or required: ' + (item ? item.getTitle() : id));
    }
  });

  const hash = form.getItemById(built.hashId);
  if (hash === null || !hash.asTextItem().isRequired()) {
    problems.push('The installer SHA-256 question is missing or not required.');
  }

  if (problems.length > 0) {
    throw new Error('The built form breaks its own rules:\n- ' + problems.join('\n- '));
  }
}

function requirable_(item) {
  switch (item.getType()) {
    case FormApp.ItemType.TEXT: return item.asTextItem();
    case FormApp.ItemType.PARAGRAPH_TEXT: return item.asParagraphTextItem();
    case FormApp.ItemType.CHECKBOX: return item.asCheckboxItem();
    default: throw new Error('Unexpected type for a personal field: ' + item.getType());
  }
}

// ---- Question helpers -------------------------------------------------------------------------

function withWarning_(help, warning) {
  return help ? help + '\n' + warning : warning;
}

function shortText_(form, title, help, opts) {
  const item = form.addTextItem()
    .setTitle(title)
    .setHelpText(withWarning_(help, opts.warning || PRIVACY))
    .setRequired(!!opts.required);
  if (opts.validation) {
    item.setValidation(opts.validation);
  }
  return item;
}

function paragraph_(form, title, help, opts) {
  return form.addParagraphTextItem()
    .setTitle(title)
    .setHelpText(withWarning_(help, opts.warning || PRIVACY))
    .setRequired(!!opts.required);
}

function choice_(form, title, help, values, required) {
  const item = form.addMultipleChoiceItem()
    .setTitle(title)
    .setChoiceValues(values)
    .setRequired(required);
  if (help) {
    item.setHelpText(help);
  }
  return item;
}

function grid_(form, title, help, rows, columns) {
  const item = form.addGridItem()
    .setTitle(title)
    .setRows(rows)
    .setColumns(columns)
    .setRequired(true);
  if (help) {
    item.setHelpText(help);
  }
  return item;
}

function scale_(form, title, lowLabel, highLabel) {
  return form.addScaleItem()
    .setTitle(title)
    .setBounds(1, 5)
    .setLabels(lowLabel, highLabel)
    .setRequired(true);
}

/**
 * Points each existing choice of a multiple-choice question at a page, in order. A question's
 * choices either all navigate or none do, so every choice gets a target.
 */
function route_(item, pages) {
  const choices = item.getChoices();
  if (choices.length !== pages.length) {
    throw new Error('"' + item.getTitle() + '" has ' + choices.length + ' choices but ' + pages.length + ' targets.');
  }
  item.setChoices(choices.map(function (choice, i) {
    return item.createChoice(choice.getValue(), pages[i]);
  }));
}
