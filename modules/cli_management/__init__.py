from termcolor import cprint, colored

from prompt_toolkit import prompt, print_formatted_text
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit import Application
from prompt_toolkit.shortcuts import clear

class CLI():
    def __init__(self, options):
        global CURRENT_OPTION
        self._options = options
        self._current_path = []
        self._current_path.append(list(self._options.keys())[0])
        CURRENT_OPTION = self._options[self._current_path[0]]

        self._prompt_completer = WordCompleter(list(CURRENT_OPTION['children'].keys()))
        self._style = Style.from_dict({
            'section': 'bg:#ffffff bold black',
            'section1': 'bg:#dd0000 bold white',
            'section2': 'bg:#ff00ff bold white',
            'section3': 'bg:#ff66ff bold white',
            'option': 'ansigreen bold',
            'descr': 'ansiyellow bold',
            'error':'bg:#ff0000 bold white',
            'completion-menu.completion': 'bg:#008888 #ffffff',
            'completion-menu.completion.current': 'bg:#00aaaa #000000',
            'scrollbar.background': 'bg:#88aaaa',
            'scrollbar.button': 'bg:#222222',
            'space':'white'
        })

    def completer(text, state):
        """Tab completion"""
        matches = [option for option in list(CURRENT_OPTION['children'].keys()) if option.startswith(text)]

        if state < len(matches):
            return matches[state]
        else:
            return None        


    def cli_options(self):
        global CURRENT_OPTION

        while True:        
            try:
                clear()
                print_formatted_text(HTML("<option>[TAB to see options | Ctrl+C or exit to terminate the program]</option>"), style=self._style)
                
                for x in CURRENT_OPTION['description']:
                    print_formatted_text(HTML(f"<descr>{x}</descr>"), style=self._style)
    
                if len(self._current_path)>1:
                    print(self._current_path)
                    path = f"<section{1}> {self._current_path[2]} </section{1}>"
                    
                    for i in range(4,len(self._current_path),2):
                        path+=f"<section{i/2}> {self._current_path[i]} </section{i/2}>"

                else:
                    path = f"<section> {self._current_path[-1]} </section>"

                choice = prompt(HTML(path+" "), completer=self._prompt_completer, style=self._style, multiline=False)
                
                if choice in CURRENT_OPTION['children']:
                    if choice == 'back' and len(self._current_path)>1:
                        self._current_path = self._current_path[:-2]
                        CURRENT_OPTION = self._options[self._current_path[0]]
                        for i in self._current_path[1:]:
                            CURRENT_OPTION = CURRENT_OPTION[i]
                        self._prompt_completer = WordCompleter(list(CURRENT_OPTION['children'].keys()))
                    elif len(CURRENT_OPTION['children'][choice]['children'].keys())>1:
                        print('ciao ciao!!!')
                        self._current_path.append('children')
                        self._current_path.append(choice)
                        CURRENT_OPTION = CURRENT_OPTION['children'][choice]
                        self._prompt_completer = WordCompleter(list(CURRENT_OPTION['children'].keys()))
                    else:
                        self._current_path.append('children')
                        self._current_path.append(choice)
                        CURRENT_OPTION = CURRENT_OPTION['children'][choice]
                        self._prompt_completer = WordCompleter(list(CURRENT_OPTION['children'].keys()))    
                elif len(CURRENT_OPTION['children']) == 1:
                    CURRENT_OPTION['function'](choice)
                    x=input()
                elif choice == 'exit':
                    break
                    
            except (KeyboardInterrupt, EOFError):
                break