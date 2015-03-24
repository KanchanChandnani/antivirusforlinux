

#include <gtk/gtk.h>

#include <signal.h>
#define SIG_TEST        44      /* we define our own signal, hard coded. */

 void get_signal(int n, siginfo_t *info, void *unused)
{
        printf("Got signal from kernel: Job finished.\n");
}

void set_signal_handler()
{
        /* Setup signal handler. */
        struct sigaction sig;
        sig.sa_sigaction = get_signal;
        sig.sa_flags = SA_SIGINFO;
        sigaction(SIG_TEST, &sig, NULL);
}

 
void show_info(GtkWidget *widget, gpointer window)
{
  GtkWidget *dialog;
  dialog = gtk_message_dialog_new(GTK_WINDOW(window),
            GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_INFO,
            GTK_BUTTONS_OK,
            "Download Completed", "title");
  gtk_window_set_title(GTK_WINDOW(dialog), "Information");
  gtk_dialog_run(GTK_DIALOG(dialog));
  gtk_widget_destroy(dialog);
}
 
void show_error(GtkWidget *widget, gpointer window)
{
  GtkWidget *dialog;
  dialog = gtk_message_dialog_new(GTK_WINDOW(window),
            GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_ERROR,
            GTK_BUTTONS_OK,
            "Error loading file");
  gtk_window_set_title(GTK_WINDOW(dialog), "Error");
  gtk_dialog_run(GTK_DIALOG(dialog));
  gtk_widget_destroy(dialog);
}
 
void show_question(GtkWidget *widget, gpointer window)
{
  GtkWidget *dialog;
  dialog = gtk_message_dialog_new(GTK_WINDOW(window),
            GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_QUESTION,
            GTK_BUTTONS_YES_NO,
            "Are you sure to quit?");
  gtk_window_set_title(GTK_WINDOW(dialog), "Question");
  gtk_dialog_run(GTK_DIALOG(dialog));
  gtk_widget_destroy(dialog);
}
 
void show_warning(GtkWidget *widget, gpointer window)
{
  GtkWidget *dialog;
  dialog = gtk_message_dialog_new(GTK_WINDOW(window),
            GTK_DIALOG_DESTROY_WITH_PARENT,
            GTK_MESSAGE_WARNING,
            GTK_BUTTONS_OK,
            "Unallowed operation");
  gtk_window_set_title(GTK_WINDOW(dialog), "Warning");
  gtk_dialog_run(GTK_DIALOG(dialog));
  gtk_widget_destroy(dialog);
}
 
int main( int argc, char *argv[])
{
 
  GtkWidget *window;
  GtkWidget *table;
 
  GtkWidget *info;
  GtkWidget *warn;
  GtkWidget *que;
  GtkWidget *err;
  GtkWidget *ok;
 
  gtk_init(&argc, &argv);
  set_signal_handler();
 
  window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_position(GTK_WINDOW(window), GTK_WIN_POS_CENTER);
  gtk_window_set_default_size(GTK_WINDOW(window), 220, 150);
  gtk_window_set_title(GTK_WINDOW(window), "Virus Alert!!");
 
  table = gtk_table_new(2, 2, TRUE);
  gtk_table_set_row_spacings(GTK_TABLE(table), 2);
  gtk_table_set_col_spacings(GTK_TABLE(table), 2);
 
  info = gtk_button_new_with_label("Info");
  warn = gtk_button_new_with_label("Warning: Virus Detected !!");
  que = gtk_button_new_with_label("Question");
  err = gtk_button_new_with_label("Error");
  ok = gtk_button_new_with_label("Ok !!");
  gtk_table_attach(GTK_TABLE(table), info, 0, 1, 0, 1, GTK_FILL, GTK_FILL, 3, 3);
  gtk_table_attach(GTK_TABLE(table), warn, 1, 2, 0, 1, GTK_FILL, GTK_FILL, 3, 3);
  gtk_table_attach(GTK_TABLE(table), que, 0, 1, 1, 2, GTK_FILL, GTK_FILL, 3, 3);
  gtk_table_attach(GTK_TABLE(table), err, 1, 2, 1, 2, GTK_FILL, GTK_FILL, 3, 3);
 
  gtk_container_add(GTK_CONTAINER(window), ok);
  gtk_container_set_border_width(GTK_CONTAINER(window), 15);
 

 
  g_signal_connect(G_OBJECT(warn), "clicked",
        G_CALLBACK(show_warning), (gpointer) window);
 
 
  gtk_widget_show_all(window);
 
  gtk_main();
 
  return 0;
}



