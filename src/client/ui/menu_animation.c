#include "menu_animation.h"

#include <ncurses.h>

#define MENU_TRANSITION_FRAMES 9
#define MENU_TRANSITION_DELAY_MS 50

static void draw_ascii_diagonal_ray(int y, int x, int sy, int sx) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  while (y >= 0 && y < rows && x >= 0 && x + 1 < cols) {
    if (sx == sy) {
      mvaddch(y, x, '\'');
      mvaddch(y, x + 1, '.');
    } else {
      mvaddch(y, x, '.');
      mvaddch(y, x + 1, '\'');
    }
    y += sy;
    x += sx * 2;
  }
}

static void draw_clipped_ascii_diagonal_ray(int y, int x, int sy, int sx) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);

  for (int i = 0; i < rows + cols; i++) {
    if (y >= 0 && y < rows) {
      if (sx == sy) {
        if (x >= 0 && x < cols) mvaddch(y, x, '\'');
        if (x + 1 >= 0 && x + 1 < cols) mvaddch(y, x + 1, '.');
      } else {
        if (x >= 0 && x < cols) mvaddch(y, x, '.');
        if (x + 1 >= 0 && x + 1 < cols) mvaddch(y, x + 1, '\'');
      }
    }
    y += sy;
    x += sx * 2;
  }
}

void draw_cube_frame(int top, int left, int height, int width) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);
  if (rows <= 0 || cols <= 0 || height < 2 || width < 2) return;

  const int bottom = top + height - 1;
  const int right = left + width - 1;

  draw_ascii_diagonal_ray(top, left - 1, -1, -1);
  draw_ascii_diagonal_ray(top, right, -1, 1);
  draw_ascii_diagonal_ray(bottom + 1, left - 2, 1, -1);
  draw_ascii_diagonal_ray(bottom + 1, right + 1, 1, 1);

  mvaddch(top, left, '.');
  mvhline(top, left + 1, '.', width - 2);
  mvaddch(top, right, '.');
  mvvline(top + 1, left, ':', height - 2);
  mvvline(top + 1, right, ':', height - 2);
  mvaddch(bottom, left, ':');
  mvhline(bottom, left + 1, '.', width - 2);
  mvaddch(bottom, right, ':');
}

static void draw_shrinking_square(int top, int left, int height, int width) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);
  if (rows <= 0 || cols <= 0 || height < 2 || width < 2) return;

  const int bottom = top + height - 1;
  const int right = left + width - 1;

  draw_clipped_ascii_diagonal_ray(top, left - 1, -1, -1);
  draw_clipped_ascii_diagonal_ray(top, right, -1, 1);
  draw_clipped_ascii_diagonal_ray(bottom + 1, left - 2, 1, -1);
  draw_clipped_ascii_diagonal_ray(bottom + 1, right + 1, 1, 1);

  for (int x = left; x <= right; x++) {
    if (x < 0 || x >= cols) continue;
    if (top >= 0 && top < rows) mvaddch(top, x, '.');
    if (bottom >= 0 && bottom < rows) mvaddch(bottom, x, '.');
  }

  for (int y = top; y <= bottom; y++) {
    if (y < 0 || y >= rows) continue;
    if (left >= 0 && left < cols) mvaddch(y, left, ':');
    if (right >= 0 && right < cols) mvaddch(y, right, ':');
  }
}

void animate_menu_box(
  int final_top, int final_left, int final_height, int final_width
) {
  int rows, cols;
  getmaxyx(stdscr, rows, cols);
  if (rows <= 0 || cols <= 0 || final_height < 2 || final_width < 2) return;

  const double aspect = (double) final_height / (double) final_width;
  int start_width = cols > rows ? cols : rows;
  int start_height = (int) (start_width * aspect);

  if (start_height < rows) {
    start_height = rows;
    start_width = (int) (start_height / aspect);
  }
  start_width += 2;
  start_height += 2;

  const int center_y = final_top + final_height / 2;
  const int center_x = final_left + final_width / 2;

  for (int i = 0; i < MENU_TRANSITION_FRAMES; i++) {
    const int step = i + 1;
    const int height = start_height + (final_height - start_height) * step /
                                        MENU_TRANSITION_FRAMES;
    const int width =
      start_width + (final_width - start_width) * step / MENU_TRANSITION_FRAMES;
    const int top = center_y - height / 2;
    const int left = center_x - width / 2;

    erase();
    draw_shrinking_square(top, left, height, width);
    refresh();
    napms(MENU_TRANSITION_DELAY_MS);
  }
}
