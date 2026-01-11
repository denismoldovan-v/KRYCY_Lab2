import os

def _esc(s: str) -> str:
    if s is None:
        return ""
    s = str(s).replace("\\", "/")
    for a, b in [
        ("_", "\\_"), ("%", "\\%"), ("&", "\\&"), ("#", "\\#"),
        ("{", "\\{"), ("}", "\\}"), ("~", "\\~{}"), ("^", "\\^{}"),
    ]:
        s = s.replace(a, b)
    return s

def build_report_tex(out_dir: str, pcap_path: str):
    tex = r"""\documentclass[11pt,a4paper]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage[polish]{babel}
\usepackage{geometry}
\geometry{margin=2.2cm}
\usepackage{graphicx}
\usepackage{booktabs}
\usepackage{hyperref}
\usepackage{float}

\title{Raport PoC: analiza flow + reguły + ML + enrichment}
\author{Denys Moldovan}
\date{\today}

\begin{document}
\maketitle

\section{Wejście}
Plik PCAP: \texttt{""" + _esc(pcap_path) + r"""}

\section{Artefakty}
Wyniki zostały zapisane w katalogu \texttt{""" + _esc(out_dir) + r"""} i obejmują m.in.:
\begin{itemize}
  \item \texttt{flows.csv} -- wyekstrahowane flow (NFStream)
  \item \texttt{pairs\_summary.csv} -- statystyki host--host
  \item \texttt{alerts.json} -- alerty z reguł Python + Sigma
  \item \texttt{ml\_predictions.csv} -- predykcje modelu ML
  \item \texttt{alerts\_over\_time.png} -- wykres alertów w czasie
  \item \texttt{map.html} -- mapa IP (opcjonalnie)
\end{itemize}

\section{Wizualizacja}
\begin{figure}[H]
\centering
\includegraphics[width=0.95\textwidth]{alerts\_over\_time.png}
\caption{Liczba alertów w czasie (agregacja).}
\end{figure}

\end{document}
"""
    path = os.path.join(out_dir, "report.tex")
    with open(path, "w", encoding="utf-8") as f:
        f.write(tex)
    return path
